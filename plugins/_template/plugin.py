from app.core.plugin import BasePlugin


class Plugin(BasePlugin):
    def analyze(self, asset, context, reporter):
        reporter.phase("Analisi esempio")
        return {
            "summary": "Analisi completata",
            "confidence": 1,
            "sections": [{"id": "summary", "data": {"asset": asset["name"]}}],
        }
