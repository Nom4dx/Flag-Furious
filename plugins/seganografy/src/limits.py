"""Central safety limits shared by parsers, decoders and external adapters.

Limits are deliberately conservative and can only be reduced by the job's
remaining budgets. They prevent nested archives, media sampling and decoder
searches from exhausting the isolated worker.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Immutable resource policy for one plugin execution.

    Input: the normalized hub context via :meth:`from_context`. Output: numeric
    caps. No exceptions beyond invalid integer conversion. Security: callers must
    check these values before allocation or extraction. Example:
    ``limits = Limits.from_context(context)``.
    """

    byte_budget: int
    output_budget: int
    max_depth: int = 3
    max_single_artifact_size: int = 32 * 1024 * 1024
    max_nested_files: int = 256
    max_entropy_scan_size: int = 32 * 1024 * 1024
    max_video_frames: int = 12
    max_decoder_attempts: int = 256
    max_archive_expansion_ratio: float = 100.0
    timeout_per_stage: int = 25
    max_tool_output: int = 1024 * 1024

    @classmethod
    def from_context(cls, context: dict) -> "Limits":
        """Build limits from hub budgets and optional plugin settings.

        Unknown settings are ignored. User values are clamped to safe maxima;
        malformed values fall back to defaults. This never expands the hub's
        byte/output grants.
        """
        options = context.get("plugin_options", {}).get("seganografy", {})

        def bounded(name, default, low, high):
            try:
                return max(low, min(high, int(options.get(name, default))))
            except (TypeError, ValueError):
                return default

        output = int(context.get("output_bytes", 128 * 1024 * 1024))
        return cls(
            byte_budget=int(context.get("byte_budget", 256 * 1024 * 1024)),
            output_budget=output,
            max_depth=bounded("max_depth", context.get("max_depth", 3), 0, 8),
            max_single_artifact_size=min(output, bounded("max_single_artifact_size", 32 * 1024 * 1024, 1024, 128 * 1024 * 1024)),
            max_nested_files=bounded("max_nested_files", 256, 1, 2000),
            max_entropy_scan_size=bounded("max_entropy_scan_size", 32 * 1024 * 1024, 4096, 128 * 1024 * 1024),
            max_video_frames=bounded("max_video_frames", 12, 1, 100),
            max_decoder_attempts=bounded("max_decoder_attempts", 256, 8, 2000),
            max_archive_expansion_ratio=float(bounded("max_archive_expansion_ratio", 100, 1, 1000)),
            timeout_per_stage=bounded("timeout_per_stage", 25, 1, 120),
            max_tool_output=bounded("max_tool_output", 1024 * 1024, 4096, 8 * 1024 * 1024),
        )
