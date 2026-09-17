---
title: Remote Code Execution Vulnerability in Nextcloud
slug: 2026-09-nextcloud-rce
description: A critical vulnerability in Nextcloud Hub, tracked as CVE-2024-28112, allows remote attackers to execute arbitrary code on the underlying application server.
date: "2026-09-17T13:09:29Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:peering-manager:peering_manager:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - rce
vendors:
  - Nextcloud
products:
  - Nextcloud Hub (< 1.8.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in Nextcloud allows a remote attacker to achieve arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The issue arises from improper handling of user-supplied input, enabling successful exploitation to compromise the application server.
    confidence_band: high
cves:
  - id: CVE-2024-28112
    cvss: 6.1
    epss: 0.00323
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3439
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Nextcloud Hub to 1.8.3 or later
      owner: IT Operations
      due: 24h
      evidence: Advisory requires mitigation of CVE-2024-28112.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nextcloud Hub to 1.8.3 or later
      owner: IT Operations
      addresses: CVE-2024-28112
      evidence: Nextcloud security advisory for WID-SEC-2026-3439.
---

Nextcloud has released a security advisory addressing a remote code execution (RCE) vulnerability, identified as CVE-2024-28112. This flaw exists within the Nextcloud Hub software and stems from the improper handling of user-supplied input during request processing. An unauthenticated or remote attacker can leverage this vulnerability to inject and execute malicious code on the application server. This level of compromise grants the attacker the ability to read, modify, or delete sensitive data stored within the Nextcloud environment and potentially pivot into the wider network infrastructure. Given the critical nature of the vulnerability, organizations running Nextcloud Hub should prioritize patching their instances to the vendor-recommended version immediately.

## Impact

Successful exploitation of CVE-2024-28112 allows an attacker to achieve full remote code execution on the server hosting Nextcloud. This provides the actor with unauthorized access to file stores, user credentials, and database contents, potentially leading to total system compromise and data exfiltration.

## Recommendation

- Identify all internet-facing Nextcloud Hub instances and audit logs for anomalous POST requests or unexpected child processes spawned by the web server user.
- Apply the security update provided by Nextcloud to resolve CVE-2024-28112 immediately.
- Review web server access logs for requests containing suspicious payload patterns that could indicate attempted exploitation of the input handling flaw.
