---
title: FreeRDP Denial of Service via Smartcard Cache Request
slug: 2026-08-freerdp-dos
description: A null pointer dereference vulnerability in FreeRDP prior to 3.29.0 allows remote attackers to trigger a crash in the client process via crafted smartcard cache requests.
date: "2026-08-01T13:51:41Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - FreeRDP
products:
  - FreeRDP
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: When smartcard emulation is enabled, attackers can send crafted smartcard cache requests with NULL lookup-name pointers to trigger strlen() on a null pointer, causing client process termination.
    confidence_band: high
cves:
  - id: CVE-2026-67288
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67288
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-ph3q-f9w8-7jf3
  - https://www.vulncheck.com/advisories/freerdp-before-denial-of-service-via-smartcard-cache
---

FreeRDP versions prior to 3.29.0 are susceptible to a null pointer dereference vulnerability within their smartcard cache request decoders. This issue occurs when the application handles SCARD_IOCTL_READCACHEA and SCARD_IOCTL_WRITECACHEA operations. Specifically, the decoder fails to properly validate NDR (Network Data Representation) pointers for the 'LookupName' field. When smartcard emulation is enabled, an attacker can transmit a crafted smartcard cache request containing a NULL pointer for this field. When the client process attempts to execute a strlen() function call on this NULL pointer, it results in an immediate crash of the FreeRDP client process. This vulnerability (CVE-2026-67288) presents a high-impact denial-of-service risk for environments utilizing FreeRDP with smartcard features enabled.

## Attack Chain

1. Attacker identifies a target system utilizing FreeRDP with smartcard emulation features enabled.
2. Attacker initiates an RDP connection to the target system.
3. Attacker negotiates smartcard redirection capabilities during the RDP handshake process.
4. Attacker sends a specially crafted SCARD_IOCTL_READCACHEA or SCARD_IOCTL_WRITECACHEA packet.
5. The packet is structured to provide a NULL pointer in the 'LookupName' field of the request.
6. The FreeRDP client process receives the malicious packet and passes it to the decoder.
7. The decoder attempts to process the NULL pointer using the strlen() function.
8. The process encounters a memory access violation, leading to an immediate termination of the FreeRDP application.

## Impact

Successful exploitation results in a persistent denial-of-service condition for the FreeRDP client process. In environments where FreeRDP is used for critical administrative access or remote workstation connectivity, this enables an attacker to disrupt operations, disconnect users, and prevent legitimate administrative access to remote systems. The vulnerability is exploitable over the network without requiring authentication.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade all instances of FreeRDP to version 3.29.0 or higher to include the fix for CVE-2026-67288.
- Disable smartcard emulation in FreeRDP configurations if it is not strictly required for business workflows to reduce the attack surface.
- Monitor endpoint process logs for abnormal termination or crashes of the FreeRDP client executable (e.g., `xfreerdp` or `wfreerdp`).
- While network-based detection is difficult due to the nature of the protocol, prioritize monitoring for unauthorized RDP connection attempts to sensitive infrastructure.
