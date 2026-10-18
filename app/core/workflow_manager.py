"""Persistent DAG executor for local extraction connectors.

Workflow definitions contain asset references, connector IDs, positions and edges.
Secrets are accepted only by ``run`` and captured by the executor future; they are
never written to SQLite. Each connector delegates to the existing isolated plugin
job manager, so resource, provenance and artifact controls remain centralized.
"""

import copy
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from app.models.contracts import JobRequest
from app.services.store import now, uid


class WorkflowManager:
    """Save, validate and execute connector workflows inside one case."""

    def __init__(self, store, assets, jobs, connectors):
        self.store, self.assets, self.jobs, self.connectors = store, assets, jobs, connectors
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.cancelled = {}
        self.futures = {}
        for run in store.list("workflow_run"):
            if run["status"] in {"queued", "running", "paused"}:
                run.update(status="partial", finished_at=now())
                run.setdefault("warnings", []).append("Workflow interrotto dal riavvio")
                store.put("workflow_run", run)

    def save(self, value, workflow_id=None):
        """Persist a validated DAG after removing all declared secret fields."""
        self.store.get("case", value.case_id)
        nodes = [n.model_dump() for n in value.nodes]
        for node in nodes:
            if node["kind"] == "asset":
                asset = self.store.get("asset", node["asset_id"])
                if asset["case_id"] != value.case_id:
                    raise ValueError("Asset di un altro caso")
            else:
                connector = self.connectors.get(node["connector_id"])
                for field in connector.get("secret_fields", []):
                    node["config"].pop(field, None)
        edges = [e.model_dump() for e in value.edges]
        node_map = {node["id"]: node for node in nodes}
        if any(node_map[edge["target"]]["kind"] != "connector" for edge in edges):
            raise ValueError("Un collegamento può terminare soltanto su un connector")
        self._order(nodes, edges)
        previous = self.store.get("workflow", workflow_id) if workflow_id else None
        if previous and previous["case_id"] != value.case_id:
            raise ValueError("Il workflow non può essere spostato in un altro caso")
        item = {
            "id": workflow_id or uid(),
            "case_id": value.case_id,
            "name": value.name,
            "nodes": nodes,
            "edges": edges,
            "created_at": previous["created_at"] if previous else now(),
            "updated_at": now(),
        }
        return self.store.put("workflow", item)

    def run(self, workflow_id, secrets):
        """Start a workflow; secret values stay only in this future closure."""
        workflow = self.store.get("workflow", workflow_id)
        connector_nodes = [node for node in workflow["nodes"] if node["kind"] == "connector"]
        if not connector_nodes:
            raise ValueError("Aggiungi almeno un connector prima di avviare il workflow")
        allowed_secrets = {
            node["id"]: set(self.connectors.get(node["connector_id"]).get("secret_fields", []))
            for node in connector_nodes
        }
        for node_id, values in secrets.items():
            if node_id not in allowed_secrets or set(values) - allowed_secrets[node_id]:
                raise ValueError("Campo segreto non dichiarato dal connector")
        if sum(x["status"] in {"queued", "running", "paused"} for x in self.store.list("workflow_run")) >= 4:
            raise ValueError("Coda workflow piena")
        run = {
            "id": uid(),
            "case_id": workflow["case_id"],
            "workflow_id": workflow_id,
            "workflow_name": workflow["name"],
            "status": "queued",
            "progress": 0,
            "created_at": now(),
            "nodes": [
                {
                    **n,
                    "status": "queued" if n["kind"] == "connector" else "ready",
                    "outputs": [n.get("asset_id")] if n["kind"] == "asset" else [],
                }
                for n in workflow["nodes"]
            ],
            "edges": workflow["edges"],
            "jobs": [],
            "warnings": [],
            "errors": [],
            "artifacts": [],
        }
        self.store.put("workflow_run", run)
        cancel = self.cancelled[run["id"]] = threading.Event()
        future = self.executor.submit(self._execute, run, copy.deepcopy(secrets), cancel)
        self.futures[run["id"]] = future
        future.add_done_callback(lambda _future, run_id=run["id"]: self._release(run_id))
        return run

    def _release(self, run_id):
        """Discard executor bookkeeping after all ephemeral inputs are erased."""
        self.cancelled.pop(run_id, None)
        self.futures.pop(run_id, None)

    def cancel(self, run_id):
        run = self.store.get("workflow_run", run_id)
        self.cancelled.get(run_id, threading.Event()).set()
        for job_id in run.get("jobs", []):
            try:
                self.jobs.cancel(job_id)
            except KeyError:
                pass
        return {"id": run_id, "cancel_requested": True}

    def _execute(self, run, secrets, cancel):
        run.update(status="running", started_at=now())
        self.store.put("workflow_run", run)
        try:
            node_map = {n["id"]: n for n in run["nodes"]}
            order = self._order(run["nodes"], run["edges"])
            parents = defaultdict(list)
            for edge in run["edges"]:
                parents[edge["target"]].append(edge["source"])
            connectors = [x for x in order if node_map[x]["kind"] == "connector"]
            completed = 0
            for node_id in order:
                node = node_map[node_id]
                if node["kind"] == "asset":
                    continue
                if cancel.is_set():
                    raise InterruptedError("Workflow annullato")
                connector = self.connectors.get(node["connector_id"])
                inputs = []
                for parent in parents[node_id]:
                    inputs.extend(node_map[parent].get("outputs", []))
                inputs = list(dict.fromkeys(x for x in inputs if x))
                if not inputs:
                    node.update(status="skipped", message="Nessun asset in ingresso")
                    run["warnings"].append(f"{connector['name']}: nessun asset in ingresso")
                    completed += 1
                    run["progress"] = round(completed / max(1, len(connectors)) * 100)
                    self.store.put("workflow_run", run)
                    continue
                node.update(status="running", started_at=now(), input_assets=inputs)
                self.store.put("workflow_run", run)
                options = self._options(connector, node, secrets.get(node_id, {}), inputs)
                request = JobRequest(
                    case_id=run["case_id"],
                    asset_ids=inputs,
                    plugin_ids=[connector["plugin_id"]],
                    recursive=False,
                    max_depth=0,
                    mode="balanced",
                    plugin_options=options,
                )
                job = self.jobs.create(request)
                run["jobs"].append(job["id"])
                node["job_id"] = job["id"]
                self.store.put("workflow_run", run)
                while True:
                    if cancel.is_set():
                        self.jobs.cancel(job["id"])
                        raise InterruptedError("Workflow annullato")
                    current = self.store.get("job", job["id"])
                    node["plugin_progress"] = current.get("progress", 0)
                    run["progress"] = round(
                        (completed + node["plugin_progress"] / 100) / max(1, len(connectors)) * 100
                    )
                    if current["status"] not in {"queued", "running", "paused"}:
                        break
                    self.store.put("workflow_run", run)
                    time.sleep(0.2)
                results = self.store.get("job", job["id"]).get("results", [])
                outputs = []
                for result in results:
                    if result.get("plugin_id") != connector["plugin_id"]:
                        continue
                    outputs.extend(x["id"] for x in result.get("derived_assets", []) if x.get("id"))
                    for artifact in result.get("artifacts", []):
                        if artifact not in run["artifacts"]:
                            run["artifacts"].append(artifact)
                        if artifact.get("asset_id"):
                            outputs.append(artifact["asset_id"])
                node.update(
                    status=current["status"] if current["status"] in {"completed", "partial"} else "failed",
                    finished_at=now(),
                    outputs=list(dict.fromkeys(outputs)),
                    output_count=len(set(outputs)),
                    job_status=current["status"],
                )
                if current["status"] == "failed":
                    run["warnings"].append(f"{connector['name']}: job fallito")
                completed += 1
                run["progress"] = round(completed / max(1, len(connectors)) * 100)
                self.store.put("workflow_run", run)
            statuses = [node_map[node_id]["status"] for node_id in connectors]
            successful = any(status in {"completed", "partial"} for status in statuses)
            final_status = (
                "completed"
                if statuses and all(status == "completed" for status in statuses)
                else "partial"
                if successful
                else "failed"
            )
            run.update(status=final_status, progress=100, finished_at=now())
        except InterruptedError as exc:
            run.update(status="cancelled", finished_at=now())
            run["warnings"].append(str(exc))
        except Exception as exc:
            run.update(status="failed", finished_at=now())
            run["errors"].append(str(exc))
        finally:
            for values in secrets.values():
                for key in list(values):
                    values[key] = ""
            self.store.put("workflow_run", run)

    @staticmethod
    def _options(connector, node, secrets, input_assets=None):
        config = {**node.get("config", {}), **secrets}
        if connector["plugin_id"] != "bruteforce":
            if connector["id"] == "bitlocker-readonly":
                # The sandbox later exposes only 66-byte FVEK artifacts from
                # these same-case inputs. Large sibling evidence stays hidden.
                config["companion_asset_ids"] = list(input_assets or [])
            return {connector["plugin_id"]: config} if config else {}
        brute = {
            k: v
            for k, v in config.items()
            if k
            in {
                "protection_type",
                "wordlists",
                "wordlist_roots",
                "max_attempts",
                "timeout_seconds",
                "workers",
                "transformations",
                "stop_on_first_success",
            }
        }
        if connector["mode"] == "known_password":
            brute["known_password"] = config.get("password", "")
        brute.update(confirmed=True, source_plugin="connector-workflow", parent_run_id=node["id"])
        return {"bruteforce": brute}

    @staticmethod
    def _order(nodes, edges):
        ids = {n["id"] for n in nodes}
        incoming = {x: 0 for x in ids}
        children = defaultdict(list)
        for edge in edges:
            if edge["source"] not in ids or edge["target"] not in ids:
                raise ValueError("Arco verso nodo inesistente")
            children[edge["source"]].append(edge["target"])
            incoming[edge["target"]] += 1
        queue = deque(x for x, v in incoming.items() if v == 0)
        order = []
        while queue:
            item = queue.popleft()
            order.append(item)
            for child in children[item]:
                incoming[child] -= 1
                queue.append(child) if incoming[child] == 0 else None
        if len(order) != len(ids):
            raise ValueError("Il workflow contiene un ciclo")
        return order

    def shutdown(self):
        for event in self.cancelled.values():
            event.set()
        self.executor.shutdown(wait=True, cancel_futures=False)
