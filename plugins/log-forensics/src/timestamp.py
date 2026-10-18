"""Timestamp parser for ISO/RFC3339, Unix, FILETIME and syslog values."""
from datetime import datetime,timezone
import re
from .timezone import resolve
FORMATS=("%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%dT%H:%M:%S%z","%Y-%m-%d %H:%M:%S%z","%Y-%m-%d %H:%M:%S","%d/%b/%Y:%H:%M:%S %z","%b %d %H:%M:%S")
def parse(value,timezone_name='UTC',reference_year=None):
    """Return normalized ISO time, raw value, timezone and confidence metadata."""
    raw='' if value is None else str(value).strip();tz,fallback=resolve(timezone_name);dt=None;confidence=.98
    try:
        number=float(raw)
        if number>116444736000000000:dt=datetime.fromtimestamp((number-116444736000000000)/10_000_000,timezone.utc);confidence=.96
        elif number>10_000_000_000:dt=datetime.fromtimestamp(number/1000,timezone.utc);confidence=.98
        elif number>1_000_000_000:dt=datetime.fromtimestamp(number,timezone.utc);confidence=.98
    except (ValueError,OverflowError,OSError):pass
    if dt is None:
        clean=re.sub(r'Z$','+00:00',raw)
        try:dt=datetime.fromisoformat(clean)
        except ValueError:
            for fmt in FORMATS:
                try:
                    if fmt=="%b %d %H:%M:%S":
                        year=reference_year or datetime.now(tz).year
                        dt=datetime.strptime(f"{year} {raw}","%Y %b %d %H:%M:%S")
                        confidence=.78
                    else:dt=datetime.strptime(raw,fmt)
                    break
                except ValueError:continue
    if dt is None:return {"timestamp":None,"timestamp_raw":raw,"timezone":timezone_name,"timestamp_confidence":0,"error":"timestamp_unparsed"}
    if dt.tzinfo is None:dt=dt.replace(tzinfo=tz);confidence=min(confidence,.82 if not fallback else .68)
    dt=dt.astimezone(timezone.utc)
    return {"timestamp":dt.isoformat().replace('+00:00','Z'),"timestamp_raw":raw,"timezone":timezone_name,"timestamp_confidence":confidence}
