"""Sysmon event mapper built on structured Windows Event XML."""
from .windows_xml import parse as _parse
def parse(data,source,context):
    """Parse Windows XML and label records from the Sysmon provider."""
    return [{**row,"parser":"sysmon"} for row in _parse(data,source,context)]
