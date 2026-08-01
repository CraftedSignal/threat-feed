---
title: 'CVE-2026-67289: CRLF Injection Vulnerability in FreeRDP'
slug: 2026-08-freerdp-crlf-injection
description: FreeRDP versions through 3.28.0 fail to sanitize control characters in RDP redirection fields, allowing malicious servers to perform HTTP request smuggling or header injection against proxy servers.
date: "2026-08-01T13:50:42Z"
lastmod: "2026-08-01T13:52:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - FreeRDP
products:
  - FreeRDP (<= 3.28.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A malicious or compromised RDP server can send a crafted redirection PDU containing embedded control characters to inject arbitrary headers/requests into the HTTP proxy CONNECT request.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This can lead to heap corruption and application crashes.
    confidence_band: med
cves:
  - id: CVE-2026-67289
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67289
updates:
  - at: "2026-08-01T13:52:15Z"
    level: L1
    summary: 'merged source coverage: Heap Buffer Overflow in FreeRDP RAIL Channel Handler'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67298
---

FreeRDP versions 3.28.0 and earlier contain a critical vulnerability (CVE-2026-67289) stemming from improper validation of CRLF and control characters within the TargetNetAddress field during RDP redirection. When a client is configured to connect via an HTTP proxy, FreeRDP propagates the attacker-controlled input directly into the proxy CONNECT request line and Host header. This flaw enables an attacker operating a malicious RDP server to execute HTTP request smuggling, inject arbitrary HTTP headers, or potentially facilitate further attacks against the proxy infrastructure or the client's internal network traversal. Because the proxy processes these smuggled requests as authenticated or authorized traffic, the impact can include unauthorized resource access or secondary exploitation. Defenders should prioritize updating to FreeRDP 3.29.0 or later to ensure proper sanitization of redirection payloads.

## Impact

Successful exploitation allows for HTTP request smuggling and header injection through the proxy, which could lead to unauthorized access to internal resources, credential theft, or bypass of proxy-based security controls. This vulnerability affects all environments using FreeRDP as a client when egressing through an HTTP proxy, regardless of the underlying operating system.

## Recommendation

- Upgrade all FreeRDP client installations to version 3.29.0 or later immediately to apply the required input sanitization for the TargetNetAddress field.
- Review HTTP proxy logs for anomalous CONNECT requests that contain unexpected control characters or header structure deviations.
- Evaluate the necessity of allowing HTTP proxy connections for RDP traffic, and consider transitioning to direct connections or hardened VPN-based access where possible.
