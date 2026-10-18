import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from app.core.execution_graph import ExecutionGraph
from app.core.result_normalizer import normalize
from app.core.flag_detector import validate_patterns
from app.services.store import uid, now


class JobManager:
    def __init__(self, settings, store, registry, assets, artifacts, sandbox):
        self.settings, self.store, self.registry = settings, store, registry
        self.assets, self.artifacts, self.sandbox = assets, artifacts, sandbox
        self.executor = ThreadPoolExecutor(max_workers=settings.max_jobs)
        self.cancelled = {}
        self.paused = {}
        self.futures = {}
        for job in store.list("job"):
            if job["status"] in ("queued", "running"):
                job.update(status="partial", finished_at=now())
                job.setdefault("warnings", []).append(
                    "Esecuzione interrotta dal riavvio; avviare un nuovo job"
                )
                store.put("job", job)

    def create(self, request):
        with self.store.lock:
            self.store.get("case", request.case_id)
            if sum(j["status"] in ("queued", "running") for j in self.store.list("job")) >= 16:
                raise ValueError("Coda job piena")
            for id in request.asset_ids:
                if self.store.get("asset", id)["case_id"] != request.case_id:
                    raise ValueError("Asset di un altro caso")
            if request.plugin_ids is not None:
                normalized_plugins = [self.registry.resolve_id(value) for value in request.plugin_ids]
                self.registry.order(normalized_plugins)
                for id in normalized_plugins:
                    if not self.registry.plugins[id]["available"]:
                        raise ValueError(f"Plugin non disponibile: {id}")
            validate_patterns(request.prefixes, request.patterns)
            options = request.model_dump()
            import json

            if len(json.dumps(options.get("plugin_options", {}), ensure_ascii=False)) > 65536:
                raise ValueError("Opzioni plugin troppo grandi")
            brute = options.get("plugin_options", {}).get("bruteforce", {})
            if brute:
                if len(str(brute.get("known_password") or "")) > 4096:
                    raise ValueError("Password troppo lunga")
                if len(brute.get("wordlists", [])) > 32 or len(brute.get("wordlist_roots", [])) > 8:
                    raise ValueError("Troppe wordlist o directory selezionate")
            encrypted_volume = options.get("plugin_options", {}).get("encrypted-volume-forensics", {})
            for field in ("password", "recovery_key"):
                if len(str(encrypted_volume.get(field) or "")) > 4096:
                    raise ValueError("Credenziale volume troppo lunga")
            if request.plugin_ids is not None:
                options["plugin_ids"] = normalized_plugins
            # Runtime secrets are captured only by the worker future. The job
            # record and API response retain a masked value, never plaintext.
            import copy

            stored_options = copy.deepcopy(options)
            stored_brute = stored_options.get("plugin_options", {}).get("bruteforce", {})
            if stored_brute.get("known_password") is not None:
                stored_brute["known_password"] = "********"
            stored_volume = stored_options.get("plugin_options", {}).get("encrypted-volume-forensics", {})
            for field in ("password", "recovery_key"):
                if stored_volume.get(field) is not None:
                    stored_volume[field] = "********"
            job = {
                "id": uid(),
                "case_id": request.case_id,
                "status": "queued",
                "created_at": now(),
                "options": stored_options,
                "results": [],
                "logs": [],
                "flags": [],
                "warnings": [],
                "graph": {"nodes": [], "edges": []},
                "progress": 0,
            }
            self.store.put("job", job)
            cancel = self.cancelled[job["id"]] = threading.Event()
            self.paused[job["id"]] = threading.Event()
            self.futures[job["id"]] = self.executor.submit(self.run, job, cancel, options)
            return job

    def cancel(self, id):
        job = self.store.get("job", id)
        if id in self.cancelled:
            self.cancelled[id].set()
        return {"id": id, "cancel_requested": job["status"] in ("running", "queued")}

    def pause(self, id):
        """Pause the isolated worker without exposing or restarting candidates."""
        job = self.store.get("job", id)
        if job["status"] != "running":
            raise ValueError("Solo un job in esecuzione può essere sospeso")
        self.paused[id].set()
        job["status"] = "paused"
        self.store.put("job", job)
        return {"id": id, "status": "paused"}

    def resume(self, id):
        """Resume a paused worker from its current attempt index."""
        job = self.store.get("job", id)
        if job["status"] != "paused":
            raise ValueError("Il job non è in pausa")
        self.paused[id].clear()
        job["status"] = "running"
        self.store.put("job", job)
        return {"id": id, "status": "running"}

    def shutdown(self):
        for event in self.cancelled.values():
            event.set()
        self.executor.shutdown(wait=True, cancel_futures=False)

    def run(self, job, cancel, runtime_options=None):
        graph = ExecutionGraph(job["graph"])
        options = runtime_options or job["options"]
        remaining = min(options["byte_budget"], self.settings.byte_budget)
        job.update(
            status="running",
            started_at=now(),
            progress=max(1, job.get("progress", 0)),
            processed_assets=0,
            current_phase="Preparazione",
            current_plugin=None,
        )
        visited = set()
        scanned = set()
        flag_values = set()
        count = 0
        active_phases = {}
        phase_steps = 0
        queue = deque((id, None) for id in options["asset_ids"])

        def save():
            self.store.put("job", job)

        def advance(candidate):
            """Move progress forward without allowing newly discovered work to rewind it."""
            value = max(0, min(95, int(candidate)))
            if value > job.get("progress", 0):
                job["progress"] = value

        def event(node, message):
            nonlocal phase_steps
            kind, data = message.get("kind"), message.get("data", {})
            if kind == "phase":
                phase_steps += 1
                job["current_phase"] = data.get("label", "Analisi")
                job["current_plugin"] = node.get("plugin_id")
                # Reporter phases provide visible movement while a long-running
                # plugin owns the worker. Recursive discovery is accounted for
                # separately after the source asset has completed.
                advance(min(35 if options["recursive"] else 88, 4 + phase_steps * 2))
                if node["id"] in active_phases:
                    previous, tick = active_phases.pop(node["id"])
                    graph.finish(previous, duration=round(time.monotonic() - tick, 3))
                phase_node = graph.add(
                    data.get("label", "Fase"),
                    "phase",
                    node["id"],
                    plugin_id=node.get("plugin_id"),
                    status="running",
                    finished_at=None,
                    **{k: v for k, v in data.items() if k not in ("label", "status", "finished_at")},
                )
                active_phases[node["id"]] = (phase_node, time.monotonic())
            elif kind == "log":
                job["logs"].append({"timestamp": now(), "node_id": node["id"], **data})
            elif kind == "partial":
                try:
                    node["partial_result"] = normalize(
                        data, node.get("plugin_id", "core"), node.get("asset_id", ""), {}
                    )
                except Exception as exc:
                    job["warnings"].append("Risultato parziale invalido: " + str(exc))
            elif kind == "visualization":
                from app.core.visualization_engine import validate_visualization

                try:
                    graph.add(
                        data.get("title", "Visualizzazione"),
                        "visualization",
                        node["id"],
                        visualization=validate_visualization(data),
                    )
                except ValueError as exc:
                    job["warnings"].append(str(exc))
            job["logs"] = job["logs"][-5000:]
            save()

        def flags_for(asset, parent, limit=None):
            nonlocal remaining
            if remaining <= 0:
                return
            cost = min(asset.get("size", 0), remaining, limit if limit is not None else remaining)
            if not self.sandbox.available:
                # The core scanner is trusted, has bounded inputs and regex deadlines.
                from app.core.flag_detector import search

                result = search(asset, {**options, "byte_budget": max(1, cost)})
            else:
                result = self.sandbox.run(
                    "flags",
                    asset,
                    context={**options, "byte_budget": max(1, cost)},
                    cancel=cancel,
                    pause=self.paused.get(job["id"]),
                )
            remaining -= cost
            node = graph.add("Flag detector", "phase", parent, result=result, asset_id=asset["id"])
            job["warnings"].extend(result.get("warnings", []))
            for flag in result.get("flags", []):
                if len(job["flags"]) >= options["max_flags"]:
                    job["warnings"].append("Limite globale flag raggiunto")
                    break
                if flag["value"] in flag_values:
                    continue
                flag_values.add(flag["value"])
                job["flags"].append(flag)
                graph.add(flag["value"], "flag", node["id"], result=flag)

        try:
            save()
            while queue:
                if cancel.is_set():
                    raise InterruptedError("Analisi annullata")
                id, parent_node = queue.popleft()
                asset = self.store.get("asset", id)
                count += 1
                job["processed_assets"] = count
                job["current_asset"] = asset.get("name", id)
                job["current_phase"] = "Identificazione asset"
                job["current_plugin"] = None
                if count > self.settings.max_pipeline_assets:
                    job["warnings"].append("Limite asset pipeline")
                    break
                node = graph.add(asset["name"], "asset", parent_node, asset_id=id, result_reference=id)
                advance(3 if count == 1 else 36 + int(count / max(1, count + len(queue)) * 58))
                identify = graph.add(
                    "Identificazione", "identification", node["id"], result=self.assets.public(asset)
                )
                if asset["type"] == "file":
                    triage = asset.get("triage", {})
                    graph.add(
                        "Magic Wrapper",
                        "plugin",
                        identify["id"],
                        plugin_id="magic-wrapper",
                        asset_id=id,
                        result=triage,
                        confidence=triage.get("confidence", 0),
                        status=triage.get("status", "partial"),
                    )
                    job["results"].append(normalize(triage, "magic-wrapper", id, {}))
                # Connector-only plugins never enter automatic triage. They are
                # considered only when a workflow or API request names them.
                compatibility = self.registry.compatible(
                    asset, include_connectors=options["plugin_ids"] is not None
                )
                # Derived assets are dispatched automatically only when a matcher
                # has concrete evidence. Generic 0.5 declarations otherwise cause
                # every recovered log to run broad triage plugins again, inflating
                # both execution time and the graph without adding useful results.
                recursive_threshold = {"quick": 0.8, "balanced": 0.7, "deep": 0.6}.get(
                    options.get("mode"), 0.7
                )
                candidates = {
                    x["plugin_id"]
                    for x in compatibility
                    if x["available"]
                    and x["compatible"]
                    and (not parent_node or x.get("score", 0) >= recursive_threshold)
                }
                selected = (
                    candidates
                    if options["plugin_ids"] is None or parent_node
                    else candidates.intersection(options["plugin_ids"])
                )
                fingerprint = asset["hashes"]["sha256"]
                if fingerprint not in scanned:
                    # Initial triage must leave a budget for the selected analyzers.
                    flags_for(
                        asset, identify["id"], max(1, min(1024**2, remaining // 2)) if selected else None
                    )
                    scanned.add(fingerprint)
                if remaining <= 0:
                    job["warnings"].append("Byte budget globale esaurito")
                    save()
                    continue
                pending = deque(self.registry.order(sorted(selected)))
                plugin_total = max(1, len(pending))
                plugin_done = 0
                completed = {}
                while pending:
                    if cancel.is_set():
                        raise InterruptedError("Analisi annullata")
                    plugin_id = pending.popleft()
                    key = (fingerprint, plugin_id)
                    if key in visited:
                        continue
                    visited.add(key)
                    plugin = self.registry.plugins[plugin_id]
                    job["current_plugin"] = plugin_id
                    job["current_phase"] = f"Avvio {plugin['manifest']['name']}"
                    plugin_node = graph.add(
                        plugin["manifest"]["name"],
                        "plugin",
                        identify["id"],
                        plugin_id=plugin_id,
                        asset_id=id,
                        status="running",
                        finished_at=None,
                    )
                    for dependency in plugin["manifest"]["dependencies"]:
                        if dependency in completed:
                            graph.data["edges"].append(
                                {
                                    "source": completed[dependency]["id"],
                                    "target": plugin_node["id"],
                                    "type": "dependency",
                                    "label": "dipende da",
                                }
                            )
                    started = time.monotonic()
                    save()
                    try:
                        if remaining <= 0:
                            raise ValueError("Byte budget globale esaurito")
                        if not plugin["available"]:
                            raise ValueError(plugin.get("error", "Plugin non disponibile"))
                        if any(
                            completed.get(d, {}).get("status") not in ("completed", "partial")
                            for d in plugin["manifest"]["dependencies"]
                        ):
                            raise ValueError("Dipendenza non completata")
                        cost = min(asset["size"], remaining, plugin["manifest"]["byte_budget"])
                        plugin_options = options.get("plugin_options", {}).get(plugin_id, {})
                        companion_assets = []
                        if plugin_id == "encrypted-volume-forensics":
                            for companion_id in plugin_options.get("companion_asset_ids", []):
                                if companion_id == id:
                                    continue
                                try:
                                    companion = self.store.get("asset", companion_id)
                                except KeyError:
                                    continue
                                if companion.get("case_id") == job["case_id"] and companion.get("size") == 66:
                                    companion_assets.append(companion)
                        raw = self.sandbox.run(
                            "analyze",
                            asset,
                            plugin,
                            {
                                **options,
                                "byte_budget": remaining,
                                "dependency_results": {
                                    d: completed[d].get("result") for d in plugin["manifest"]["dependencies"]
                                },
                                "companion_assets": companion_assets,
                            },
                            cancel,
                            lambda e, current_node=plugin_node: event(current_node, e),
                            pause=self.paused.get(job["id"]),
                        )
                        remaining -= cost
                        result = normalize(raw, plugin_id, id, plugin["output_schema"])
                        for flag in result["flags"]:
                            if len(job["flags"]) >= options["max_flags"]:
                                break
                            value = flag.get("value", flag.get("candidate"))
                            if value and value not in flag_values:
                                flag_values.add(value)
                                item = {
                                    **flag,
                                    "value": value,
                                    "asset_id": id,
                                    "plugin_id": plugin_id,
                                    "source": flag.get("source", id),
                                    "method": flag.get("method", "plugin"),
                                }
                                job["flags"].append(item)
                                graph.add(value, "flag", plugin_node["id"], result=item)
                        new_assets = []
                        produced = result.pop("derived_assets", []) + result.pop("artifacts", [])
                        result["artifacts"] = []
                        result["derived_assets"] = []
                        for produced_index, item in enumerate(produced):
                            try:
                                artifact, derived = self.artifacts.register(item, asset, plugin_id, job["id"])
                                result["artifacts"].append(artifact)
                                result["derived_assets"].append(self.assets.public(derived))
                                artifact_node = graph.add(
                                    artifact["name"],
                                    "artifact",
                                    plugin_node["id"],
                                    artifact_id=artifact["id"],
                                    result=artifact,
                                )
                                new_assets.append((derived, artifact_node))
                            except Exception as exc:
                                message = str(exc)
                                if message == "Limite asset del caso raggiunto":
                                    omitted = len(produced) - produced_index
                                    result["warnings"].append(
                                        f"Limite asset del caso raggiunto: {omitted} artefatti non registrati"
                                    )
                                    result["status"] = "partial"
                                    break
                                result["warnings"].append(message)
                                result["status"] = "partial"
                        for derived, artifact_node in new_assets:
                            if (
                                options["recursive"]
                                and derived["depth"] <= min(options["max_depth"], self.settings.max_depth)
                                and derived["hashes"]["sha256"] not in scanned
                            ):
                                queue.append((derived["id"], artifact_node["id"]))
                            else:
                                graph.add(
                                    derived["name"],
                                    "asset",
                                    artifact_node["id"],
                                    asset_id=derived["id"],
                                    status="skipped",
                                    reason="Profondità, duplicato o ricorsione disabilitata",
                                )
                                if derived["hashes"]["sha256"] not in scanned:
                                    flags_for(derived, artifact_node["id"])
                                    scanned.add(derived["hashes"]["sha256"])
                        for visual in result["visualizations"]:
                            graph.add(
                                visual.get("title", "Visualizzazione"),
                                "visualization",
                                plugin_node["id"],
                                visualization=visual,
                            )
                        text = json.dumps(
                            {k: v for k, v in result.items() if k not in ("derived_assets", "artifacts")},
                            ensure_ascii=False,
                        )
                        flags_for(
                            {"id": id, "content": text, "size": len(text.encode()), "type": "text"},
                            plugin_node["id"],
                        )
                        for request in result.get("requested_plugins", []):
                            if request not in candidates:
                                result["warnings"].append(f"Plugin richiesto non compatibile: {request}")
                            else:
                                pending.extend(self.registry.order([request]))
                    except InterruptedError:
                        raise
                    except Exception as exc:
                        result = normalize(
                            {
                                **plugin_node.pop("partial_result", {}),
                                "status": "partial" if isinstance(exc, TimeoutError) else "failed",
                                "summary": str(exc),
                                "errors": [str(exc)],
                            },
                            plugin_id,
                            id,
                            plugin["output_schema"],
                        )
                        graph.add(str(exc), "error", plugin_node["id"], status="failed")
                    result["metrics"]["duration"] = round(time.monotonic() - started, 3)
                    if plugin_node["id"] in active_phases:
                        last_phase, tick = active_phases.pop(plugin_node["id"])
                        graph.finish(last_phase, result["status"], duration=round(time.monotonic() - tick, 3))
                    graph.finish(
                        plugin_node,
                        result["status"],
                        result=result,
                        duration=result["metrics"]["duration"],
                        confidence=result["confidence"],
                    )
                    completed[plugin_id] = plugin_node
                    job["results"].append(result)
                    plugin_done += 1
                    if count == 1:
                        primary_span = 30 if options["recursive"] else 88
                        advance(6 + plugin_done / plugin_total * primary_span)
                    save()
                if queue:
                    advance(36 + count / (count + len(queue)) * 58)
                else:
                    advance(95)
                save()
            job["status"] = (
                "partial"
                if job["warnings"] or any(r["status"] in ("partial", "failed") for r in job["results"])
                else "completed"
            )
        except InterruptedError:
            job["status"] = "cancelled"
        except Exception as exc:
            job["status"] = "failed"
            job["warnings"].append(str(exc))
            graph.add(str(exc), "error", status="failed")
        finally:
            # Runtime connector credentials are deliberately short-lived. The
            # persisted job already contains a mask; erase the worker copy before
            # the future releases its frame.
            runtime_brute = options.get("plugin_options", {}).get("bruteforce", {})
            if runtime_brute.get("known_password") is not None:
                runtime_brute["known_password"] = ""
            runtime_volume = options.get("plugin_options", {}).get("encrypted-volume-forensics", {})
            for field in ("password", "recovery_key"):
                if runtime_volume.get(field) is not None:
                    runtime_volume[field] = ""
            for node in graph.data["nodes"]:
                if node["status"] == "running":
                    graph.finish(node, job["status"])
            report_node = graph.add(
                "Report del caso", "report", status=job["status"], result_reference=job["case_id"]
            )
            targets = {e["source"] for e in graph.data["edges"]}
            for node in graph.data["nodes"][:-1]:
                if node["id"] not in targets:
                    graph.data["edges"].append(
                        {
                            "source": node["id"],
                            "target": report_node["id"],
                            "type": "result",
                            "label": "report",
                        }
                    )
            job.update(
                finished_at=now(),
                progress=100,
                bytes_remaining=remaining,
                current_phase="Analisi terminata",
                current_plugin=None,
            )
            save()
