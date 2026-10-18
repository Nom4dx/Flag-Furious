"""Password-free requests to the shared bruteforce connector."""


def build(volume:dict,hash_artifacts:list[dict],asset:dict,protectors:list[dict])->dict:
    """Create a manual workflow request while retaining volume provenance."""
    return {"type":"password_required","source_plugin":"encrypted-volume-forensics","artifact_id":asset.get("id",volume["id"]),
            "artifact_path":asset.get("path"),"detected_format":"BitLocker","protection_type":"bitlocker","operation":"unlock",
            "hash_artifact":hash_artifacts[0]["artifact_id"] if hash_artifacts else None,"allowed_modes":["known_password","known_recovery_key","wordlist","john","hashcat"],
            "supported_adapters":["bitlocker_adapter"],"parent_analysis_id":asset.get("analysis_id"),"request_bruteforce":True,
            "ui_required":True,"metadata":{"offset":volume["offset"],"length":volume["length"],"volume_id":volume["id"],"protector_types":[row["type"] for row in protectors]}}
