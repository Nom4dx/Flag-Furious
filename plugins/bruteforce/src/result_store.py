"""Ephemeral result store; persistent payloads never include raw passwords."""
class ResultStore(dict):
    """Store session responses in memory and remove them explicitly."""
    def forget(self,key):self.pop(key,None)
