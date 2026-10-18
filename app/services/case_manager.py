import shutil
from app.services.store import uid, now


class CaseManager:
    def __init__(self, settings, store):
        self.settings, self.store = settings, store

    def create(self, name):
        case = {"id": uid(), "name": name[:200] or "Nuovo caso", "created_at": now(), "audit": []}
        (self.settings.storage / "cases" / case["id"]).mkdir()
        return self.store.put("case", case)

    def delete(self, id):
        with self.store.lock:
            self.store.get("case", id)
            active_jobs = {"queued", "running", "paused"}
            active_workflows = {"queued", "running", "paused"}
            if any(j["status"] in active_jobs for j in self.store.list("job", id)):
                raise ValueError("Annullare o riprendere e attendere i job attivi prima di eliminare il caso")
            if any(r["status"] in active_workflows for r in self.store.list("workflow_run", id)):
                raise ValueError("Annullare e attendere i workflow attivi prima di eliminare il caso")
            shutil.rmtree(self.settings.storage / "cases" / id)
            for path in (self.settings.storage / "reports").glob(id + ".*"):
                path.unlink()
            self.store.delete_case(id)
