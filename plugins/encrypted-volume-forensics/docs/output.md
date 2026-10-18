# Output example

```json
{
  "plugin_id": "encrypted-volume-forensics",
  "status": "completed",
  "summary": "1 volumi BitLocker, 1 protector, 2 hash, 0 sbloccati",
  "unlock_requests": [{
    "source_plugin": "encrypted-volume-forensics",
    "protection_type": "bitlocker",
    "operation": "unlock",
    "ui_required": true
  }],
  "metrics": {"bitlocker_volumes": 1, "original_modified": false}
}
```

`artifacts` can include password-hash descriptors, a decrypted filesystem image,
selected files and the JSON report. Paths are available to the Hub artifact
manager but are omitted from dashboard section copies.
