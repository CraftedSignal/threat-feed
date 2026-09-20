---
title: Remote Stack-Based Buffer Overflow in Comfast CF-N1-S
slug: 2026-09-comfast-buffer-overflow
description: A stack-based buffer overflow vulnerability in the Comfast CF-N1-S Web Management Interface (CVE-2026-94003) allows remote, unauthenticated attackers to execute arbitrary code via a malicious URI request.
date: "2026-09-20T12:20:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:comfast:cf_n1_s:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-infrastructure
vendors:
  - Comfast
products:
  - CF-N1-S (2.6.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The manipulation leads to stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-94003
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94003
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict inbound internet access to CF-N1-S Web Management Interfaces.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-94003 remote exploitability
  mitigation_plan:
    - priority: immediate
      action: Disable external access to /cgi-bin/mbox-config or the entire web management UI.
      owner: IT Operations
      addresses: CVE-2026-94003
      evidence: NVD vulnerability disclosure
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-94003, affects the Web Management Interface of Comfast CF-N1-S firmware version 2.6.0.1. The flaw exists within the get_css_path_from_uri function located in the /cgi-bin/mbox-config script. Because this endpoint is accessible via the web interface and does not require authentication, a remote attacker can trigger the overflow by sending a specially crafted HTTP request. The vulnerability is publicly disclosed, and proof-of-concept exploits exist, posing a high risk for full device compromise, remote code execution, or persistent denial of service. Defenders should prioritize restricting access to the management interface of these devices from untrusted networks.

## Impact

Successful exploitation allows for unauthenticated remote code execution with root-level privileges on the affected CF-N1-S devices. Given the nature of the vulnerability, the entire device can be fully compromised, leading to complete loss of confidentiality, integrity, and availability. This is particularly critical for networking hardware that may reside at the edge of corporate or residential networks.

## Recommendation

- Restrict network access to the Web Management Interface of all Comfast CF-N1-S devices to authorized management VLANs or VPNs only.
- Monitor web server access logs for anomalous, excessively long, or malformed GET/POST requests targeted at /cgi-bin/mbox-config.
- Ensure perimeter firewalls block unsolicited inbound traffic to the web management ports (typically 80/443) of networking equipment from the public internet.
