"""Normalize unlocked artifacts for re-entry into the Hub pipeline."""
def derived(items,parent,source_plugin,secret_ref,adapter):
    """Add provenance without copying a raw secret into persistent output."""
    return [{**x,'parent_artifact_id':parent,'source_plugin':source_plugin,'unlock_plugin':'bruteforce','adapter':adapter,'password_verified':True,'secret_ref':secret_ref,'status':'unlocked'} for x in items]
