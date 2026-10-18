from app.services.store import uid, now


class ExecutionGraph:
    def __init__(self, data=None):
        self.data = data or {"nodes": [], "edges": []}

    def add(self, label, type, parent=None, **values):
        node = {
            "id": uid(),
            "label": label,
            "type": type,
            "status": "completed",
            "started_at": now(),
            "finished_at": now(),
            "duration": 0,
            **values,
        }
        self.data["nodes"].append(node)
        if parent:
            self.data["edges"].append(
                {
                    "source": parent,
                    "target": node["id"],
                    "type": "execution",
                    "label": "produce" if type in ("asset", "artifact") else "analizza",
                }
            )
        return node

    def finish(self, node, status="completed", **values):
        node.update(status=status, finished_at=now(), **values)
