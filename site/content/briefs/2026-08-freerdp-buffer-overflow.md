---
title: Heap-based Buffer Overflow in FreeRDP Windows Clipboard Client
slug: 2026-08-freerdp-buffer-overflow
description: A heap-based buffer overflow in FreeRDP versions 3.29.0 and earlier allows a malicious RDP server to execute an out-of-bounds write in the memory of a paste consumer process when handling clipboard file transfers.
date: "2026-08-02T13:35:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-access
  - windows
  - rdp
vendors:
  - FreeRDP
products:
  - FreeRDP
affected_os:
  - Windows
cves:
  - id: CVE-2026-68579
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68579
---

CVE-2026-68579 is a critical heap-based buffer overflow vulnerability residing in the Windows clipboard client component of FreeRDP, specifically within the CliprdrStream_Read function in file client/Windows/wf_cliprdr.c. The vulnerability occurs when the RDP client interacts with a malicious or compromised RDP server. During a clipboard file transfer operation, the consumer process (such as Windows Explorer) invokes IStream::Read with a specific buffer size. The CliprdrStream_Read function incorrectly trusts the server-supplied length (req_fsize) when copying data into the caller's fixed-size buffer, rather than respecting the caller's buffer constraint. An attacker can exploit this by returning an oversized CB_FILECONTENTS_RESPONSE, triggering a heap-based out-of-bounds write in the target process. This vulnerability impacts all versions of FreeRDP up to and including 3.29.0 and requires successful connection to a malicious RDP server followed by a user-initiated clipboard paste action.

## Impact

Successful exploitation of this vulnerability enables an attacker to perform an out-of-bounds write into the heap memory of the process executing the paste operation, typically explorer.exe. This can lead to arbitrary code execution within the context of the user running the RDP client session, potentially resulting in full system compromise, exfiltration of sensitive information, or the deployment of further payloads. The scope of impact includes all enterprise environments leveraging FreeRDP clients to connect to remote or third-party RDP services.

## Recommendation

1. Upgrade all FreeRDP client installations to version 3.30.0 or later to patch the vulnerability in CliprdrStream_Read (CVE-2026-68579).
2. Implement strict controls on RDP client usage, restricting connections only to known, trusted, and managed RDP servers.
3. Deploy EDR solutions to monitor for anomalous memory access or unexpected child process spawning from explorer.exe or processes identified as RDP clipboard consumers.
