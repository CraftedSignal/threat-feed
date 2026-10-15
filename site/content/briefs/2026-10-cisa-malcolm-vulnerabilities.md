---
title: Multiple High-Severity Vulnerabilities in CISA Malcolm
slug: 2026-10-cisa-malcolm-vulnerabilities
description: CISA Malcolm versions v26.07.1 and earlier contain multiple high-severity vulnerabilities, including authentication bypass, SSRF, and authorization flaws, allowing unauthenticated or low-privileged users to gain administrative control.
date: "2026-10-15T17:00:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cisa:malcolm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - network-security
  - malcolm
  - authentication-bypass
  - ssrf
vendors:
  - CISA
products:
  - Malcolm (<=v26.07.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated network caller can reach the Arkime backend while supplying a forged, auto-provisioned identity.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The passwordSecret is hardcoded to the public value 'Malcolm'.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: An authenticated user can craft a specially formatted request path to bypass role-based restrictions and reach administrative or role gated endpoints.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-280-01
  - https://www.cve.org/CVERecord?id=CVE-2026-107336
  - https://www.cve.org/CVERecord?id=CVE-2026-107333
  - https://www.cve.org/CVERecord?id=CVE-2026-107362
  - https://www.cve.org/CVERecord?id=CVE-2026-107361
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Malcolm to v26.08.0 immediately.
      owner: IT Operations
      due: 24h
      evidence: Vendor fix provided in ICSA-26-280-01
  mitigation_plan:
    - priority: immediate
      action: Block access to port 8005 from external or untrusted network zones.
      owner: IT Operations
      addresses: CVE-2026-107361
      evidence: 'The Arkime live capture service in Malcolm runs with network_mode: host, exposing port 8005.'
---

CISA Malcolm, an open-source network traffic analysis tool, is affected by multiple high-severity vulnerabilities in versions v26.07.1 and prior (CVE-2026-107336, CVE-2026-107333, CVE-2026-107362, CVE-2026-107361, CVE-2026-107337, CVE-2026-107335, and CVE-2026-107334). These flaws affect critical components including the nginx reverse proxy, the Arkime backend, and the file-upload service. Attackers can exploit nginx configuration mismatches to bypass authentication, utilize path normalization inconsistencies to circumvent role-based access controls, and leverage the FilePond PHP server to perform server-side request forgery (SSRF). Additionally, the Arkime live capture service is exposed with a hardcoded password secret and trusts external identity headers, allowing network-adjacent attackers to impersonate users. These vulnerabilities impact critical infrastructure sectors, including Energy, Information Technology, and Water and Wastewater Systems.

## Attack Chain

1. An attacker identifies a target Malcolm deployment through network scanning or reconnaissance.
2. The attacker crafts a request using a path segment that bypasses the nginx reverse proxy regex matcher for the Arkime shortcut, evading intended authentication (CVE-2026-107336).
3. The attacker injects an X-Forwarded-User header into the request to trigger auto-provisioning of an administrative identity in the Arkime backend.
4. The attacker accesses gated administrative or management interfaces by crafting request paths that exploit the normalization inconsistency between the Lua-based RBAC layer and nginx routing (CVE-2026-107333).
5. The attacker interacts with the FilePond fetch API to force the server to perform requests to internal resources, leveraging SSRF to exfiltrate or manipulate internal data (CVE-2026-107362).
6. The attacker optionally connects directly to the Arkime live capture service on port 8005, bypassing the reverse proxy entirely to utilize the hardcoded "Malcolm" password secret (CVE-2026-107361).
7. The attacker escalates privileges and gains full administrative control over the Malcolm instance, potentially accessing intercepted network traffic or configuration secrets.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated or unauthorized attackers to gain administrative access to Malcolm deployments. This results in the compromise of sensitive network traffic data analyzed by the tool, exposure of infrastructure configurations, and the ability to pivot within the host environment. Given its role in monitoring critical infrastructure, the impact includes potential espionage, disruption of security visibility, and the unauthorized control of network monitoring assets.

## Recommendation

1. Upgrade all CISA Malcolm instances to version v26.08.0 or later to apply vendor-provided fixes.
2. Restrict network access to the Arkime live capture service (port 8005) to authorized internal management segments only, preventing direct external connectivity.
3. Implement egress filtering on the Malcolm host to prevent exploitation of the SSRF vulnerability in the file-upload component.
4. Review and harden nginx proxy configurations if immediate patching is not possible, focusing on explicit authentication enforcement for all location blocks.
