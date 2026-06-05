---
description: "Begin a CTF run against a target URL or IP"
---

Begin reconnaissance on the target: $ARGUMENTS

Phase 1 (Recon):
- Run nmap -sV -sC -p- against the target.
- Identify all open ports and services.
- For web services, fetch the root page with curl and note the stack.

When recon is complete, advance to enumeration.
