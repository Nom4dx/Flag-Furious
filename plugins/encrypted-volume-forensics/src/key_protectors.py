"""Key-protector normalization with conservative confidence labels."""

KNOWN={"clear_key","tpm","startup_key","tpm_and_pin","recovery_password","password","certificate","external_key"}


def normalize(rows: list[dict]) -> list[dict]:
    """Fill the common schema without ever adding key or password material."""
    result=[]
    for index,row in enumerate(rows,1):
        kind=row.get("type","unknown")
        result.append({"protector_id":row.get("protector_id",f"protector-{index}"),"type":kind,"guid":row.get("guid"),
                       "version":row.get("version"),"offset":row.get("offset"),"length":row.get("length"),
                       "status":"recognized" if kind in KNOWN else "unknown","requires_user_secret":kind not in {"clear_key"},
                       "confidence":row.get("confidence",.95 if kind in KNOWN else .55),"parser":row.get("parser","unknown")})
    return result
