---
title: FreeRDP Double-Free Vulnerability (CVE-2026-64621)
slug: 2026-07-freerdp-double-free
description: A double-free vulnerability exists in FreeRDP versions 3.x through 3.27.1 within the freerdp_client_rdp_file_apply_to_settings() function, specifically when parsing the selectedmonitors field of a .rdp connection file. An attacker can exploit this by convincing a victim to open a crafted .rdp file containing oversized monitor tokens, leading to a size-controlled double-free in FreeRDP CLI clients like xfreerdp, sdl-freerdp, or wlfreerdp. This vulnerability can result in denial of service or potentially lead to arbitrary code execution.
date: "2026-07-20T12:29:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - double-free
  - linux
vendors:
  - FreeRDP Project
products:
  - FreeRDP (3.x through 3.27.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker who convinces a victim to open a crafted .rdp file
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: trigger a size-controlled double-free in any FreeRDP CLI client... This vulnerability can result in denial of service or potentially lead to arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-64621
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64621
---

A significant double-free vulnerability, identified as CVE-2026-64621, affects FreeRDP versions 3.x through 3.27.1. This flaw resides within the `freerdp_client_rdp_file_apply_to_settings()` function, specifically during the parsing of the `selectedmonitors` field in a .rdp connection file. The `MonitorIds` array is allocated, but an error path during `strtoul` parsing leads to its premature deallocation without clearing the pointer. Consequently, when the FreeRDP client performs its routine cleanup via `freerdp_settings_free()`, it attempts to free the same memory region again, resulting in a double-free condition. Attackers can exploit this by creating a specially crafted .rdp file with oversized monitor tokens and convincing a victim to open it using any FreeRDP command-line interface (CLI) client such as xfreerdp, sdl-freerdp, or wlfreerdp. This vulnerability can lead to client application crashes, causing denial of service, and potentially enabling remote code execution.

## Attack Chain

1. An attacker crafts a malicious `.rdp` connection file containing oversized `MonitorIds` tokens within the `selectedmonitors` field.
2. The attacker delivers this crafted `.rdp` file to a victim, typically via email, a malicious website, or a file-sharing service.
3. The victim opens the malicious `.rdp` file using an affected FreeRDP CLI client (e.g., `xfreerdp`, `sdl-freerdp`, or `wlfreerdp`).
4. The FreeRDP client's `freerdp_client_rdp_file_apply_to_settings()` function begins parsing the `selectedmonitors` field from the `.rdp` file.
5. An internal error occurs during the `strtoul` parsing of the oversized monitor tokens, triggering an error handling path.
6. On this error path, the `MonitorIds` array is freed, but the `settings->MonitorIds` pointer is not cleared, leaving it dangling.
7. Later, during the FreeRDP client's normal teardown process, the `freerdp_settings_free()` function attempts to deallocate the `settings->MonitorIds` buffer again.
8. This second free operation on an already freed memory region causes a double-free, leading to memory corruption, a crash of the FreeRDP client, and potential remote code execution.

## Impact

Successful exploitation of CVE-2026-64621 results in a denial of service (DoS) for users of FreeRDP CLI clients, as the application will crash when attempting to process the malformed `.rdp` file. While the primary immediate impact is a client-side crash, memory corruption vulnerabilities like double-frees can often be leveraged by skilled attackers to achieve more severe consequences, including arbitrary code execution. If remote code execution is achieved, an attacker could gain control over the victim's system, leading to data compromise, system manipulation, or further network penetration. The vulnerability impacts anyone using vulnerable versions of FreeRDP CLI clients to connect to RDP sessions.

## Recommendation

* Patch CVE-2026-64621 by updating all FreeRDP installations to version 3.28.0 or later immediately.
* Educate users about the risks of opening untrusted `.rdp` files.
* Implement email and web filtering to block or quarantine `.rdp` files from unknown or suspicious sources to prevent the initial delivery vector.
