"""Timezone resolution using the standard-library IANA database."""
from datetime import timezone as utc_timezone
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

def resolve(name:str|None):
    """Return a configured ZoneInfo or UTC with an explicit fallback flag."""
    if not name:return utc_timezone.utc,True
    try:return ZoneInfo(name),False
    except ZoneInfoNotFoundError:return utc_timezone.utc,True
