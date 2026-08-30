---
title: WWBN AVideo SSRF Filter Bypass via NAT64 Hex Encoding
slug: 2026-08-wwbn-avideo-ssrf
description: WWBN AVideo is vulnerable to a Server-Side Request Forgery (SSRF) bypass in the isSSRFSafeURL function due to improper normalization of hex-encoded NAT64 addresses.
date: "2026-08-30T17:11:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can bypass SSRF protections by supplying hex-encoded NAT64 addresses like 64:ff9b::a9fe:a9fe to reach cloud metadata services and loopback interfaces.
    confidence_band: high
cves:
  - id: CVE-2026-82648
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82648
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review server access logs for requests containing hex-encoded IPv6 addresses targeting internal metadata endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-82648 exploitation vector involves NAT64 hex-encoded addresses
  mitigation_plan:
    - priority: immediate
      action: Patch AVideo to the latest version as recommended by WWBN
      owner: IT Operations
      addresses: CVE-2026-82648
      evidence: Source confirms vulnerability in AVideo isSSRFSafeURL function
---

WWBN AVideo contains a server-side request forgery (SSRF) vulnerability identified as CVE-2026-82648, located within the isSSRFSafeURL function. The vulnerability stems from a failure to correctly normalize NAT64 addresses when they are presented in a hexadecimal format. Because the function does not account for these specific representations, attackers can bypass existing URL filtering protections. By crafting malicious requests containing NAT64 addresses such as 64:ff9b::a9fe:a9fe, an unauthorized actor can force the application to perform requests against restricted internal resources, including cloud metadata services (e.g., 169.254.169.254) and local loopback interfaces. This flaw is particularly significant in cloud-hosted environments where metadata services store sensitive IAM credentials or instance configuration details. Successful exploitation allows an attacker to interact with internal network segments that are otherwise protected from external reach, potentially resulting in credential theft or further lateral movement within the hosting infrastructure.

## Impact

Successful exploitation allows unauthenticated attackers to bypass SSRF protections, enabling unauthorized interaction with internal cloud metadata services and local network resources. This can result in the exfiltration of instance-level credentials, sensitive configuration data, or internal system exploitation, compromising the confidentiality and integrity of the AVideo server instance.

## Recommendation

- Audit web application logs for HTTP requests containing unusual IPv6 NAT64 or hex-encoded address strings directed at internal hostnames or IP ranges.
- Implement a secondary validation layer at the network edge or application-level proxy to verify that requests originating from AVideo are not destined for reserved or private IP ranges, regardless of the encoding used in the URL.
- Monitor for unauthorized access attempts to local cloud metadata services from the AVideo application host.
- Review all AVideo instance configurations to ensure they are updated to the latest vendor-provided patches that resolve CVE-2026-82648.
