"""Ephemeral credential selection; returned records are safe to persist."""

from .recovery_key import validate


def select(options: dict) -> tuple[str | None, str | None, dict]:
    """Return secret and method in memory plus a masked audit record.

    Password and recovery key options are consumed only when ``unlock`` is true.
    The caller must discard the first return value after the attempt.
    """
    if not options.get("unlock"):
        return None,None,{"status":"not_requested","password_display":None}
    if options.get("recovery_key"):
        checked=validate(options["recovery_key"])
        return (checked["normalized"] if checked["valid"] else None),"recovery_password",{"status":"format_valid" if checked["valid"] else "invalid_format","password_display":checked["masked"],"validation":checked["reason"]}
    if "password" in options:
        value=str(options.get("password", ""))
        return value,"password",{"status":"provided","password_display":"********","length":len(value)}
    return None,None,{"status":"missing","password_display":None}
