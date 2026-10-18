class BasePlugin:
    """All inputs/outputs are JSON; paths refer only to the worker sandbox."""

    def can_handle(self, asset, context):
        return {"compatible": True, "score": 0.5, "reasons": ["Declared matcher"]}

    def validate(self, asset, context):
        return {"valid": True}

    def analyze(self, asset, context, reporter):
        raise NotImplementedError

    def extract_artifacts(self, asset, context, reporter):
        return []

    def create_assets(self, asset, context, reporter):
        return []

    def create_visualizations(self, results, context):
        return []

    def search_flags(self, results, context):
        return []

    def cleanup(self, context):
        pass
