---
title: Remote Command Injection in H3C Magic NX15 Router
slug: 2026-10-h3c-magic-nx15-rce
description: An unauthenticated command injection vulnerability in the sub_416874 function of H3C Magic NX15 (100R017) allows remote attackers to execute arbitrary system commands via /usr/bin/usrlist.
date: "2026-10-20T00:30:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:h3c:magic_nx15:100r017:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-device
vendors:
  - H3C
products:
  - Magic NX15 (100R017)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Performing a manipulation results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-112370
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112370
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all H3C Magic NX15 devices on the network and verify current firmware version.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects firmware 100R017.
  mitigation_plan:
    - priority: immediate
      action: Disable remote administrative access from the public internet and move management interfaces to isolated internal networks.
      owner: IT Operations
      addresses: CVE-2026-112370
      evidence: Vulnerability allows remote unauthenticated command injection.
---

CVE-2026-112370 is a critical command injection vulnerability affecting H3C Magic NX15 routers running firmware version 100R017. The vulnerability resides within the function sub_416874 inside the binary /usr/bin/usrlist. By sending specially crafted input to the targeted function, a remote, unauthenticated attacker can achieve arbitrary operating system command execution with the privileges of the underlying application. Public proof-of-concept exploits for this vulnerability are available, significantly increasing the risk of exploitation by threat actors. Due to the nature of the device as an internet-facing edge router, this flaw presents a high risk for unauthorized network access, lateral movement, or complete device compromise.

## Impact

Successful exploitation allows for full remote compromise of the H3C Magic NX15 router. Attackers can gain persistent access, facilitate network reconnaissance, intercept traffic, or integrate the device into a botnet. This vulnerability is particularly dangerous for small office and home office (SOHO) deployments where these devices typically manage internet connectivity and local network segmentation.

## Recommendation

Prioritize the identification and patching of all H3C Magic NX15 devices within the network environment. Since the vendor was contacted during the disclosure process, check for firmware updates beyond 100R017 that address CVE-2026-112370. Until firmware can be updated, restrict management interfaces of all networking hardware to internal, trusted management networks only, and disable remote administrative access from the public internet. Ensure that edge network traffic is inspected for anomalous command-injection patterns directed at router management endpoints.
