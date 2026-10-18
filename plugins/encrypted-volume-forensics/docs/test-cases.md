# Test cases

Automated fixtures cover a whole-volume FVE VBR, FVE at an MBR partition offset,
GPT CRC and backup handling, damaged metadata offsets, recovery-password format,
Windows memory-pool FVEK carving, scan truncation, workflow companion-key
forwarding, loader discovery, normalized output and secret masking. Tool
availability is inventoried without making the suite depend on it.

When authorized real evidence is supplied, place every related image in the same
case and set the expected flag prefix. Bitlocker-1 must produce metadata and an
explicit unlock request before recovery runs through the connector. Bitlocker-2
must first produce memory FVEK artifacts; connect the protected image and one or
more candidate artifacts to the read-only BitLocker connector. A local optional
regression verifies the known Bitlocker-1 fixture end to end without changing it.
