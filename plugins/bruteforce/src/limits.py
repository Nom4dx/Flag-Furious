"""Resource caps for deterministic local password recovery."""
from dataclasses import dataclass
@dataclass(frozen=True)
class Limits:
    """Caps attempts, time, workers and extracted bytes; values are clamped."""
    max_attempts:int=100000; timeout_seconds:int=900; workers:int=1; max_output:int=128*1024*1024; max_ratio:int=100
    @classmethod
    def from_context(cls,c):
        o=c.get("plugin_options",{}).get("bruteforce",{})
        def n(k,d,a,b):
            try:return max(a,min(b,int(o.get(k,d))))
            except (TypeError,ValueError):return d
        return cls(n("max_attempts",100000,1,10_000_000),n("timeout_seconds",900,1,3600),n("workers",1,1,16),n("max_output",128*1024**2,1024,512*1024**2),n("max_ratio",100,1,1000))
