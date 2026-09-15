---
title: Arbitrary Code Execution Vulnerability in Octopus Deploy Server
slug: 2026-09-octopus-deploy-rce
description: A vulnerability in Octopus Deploy Server allows a remote attacker to execute arbitrary code, potentially leading to full system compromise of the application instance.
date: "2026-09-15T13:05:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:octopus:octopus_deploy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cs-technologies:evolution:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - cicd
vendors:
  - Octopus Deploy
products:
  - Octopus Deploy Server (<= 2.04.560.31.03.2024)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in Octopus Deploy Server allows a remote attacker to execute arbitrary code on the affected server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A vulnerability in Octopus Deploy Server allows a remote attacker to execute arbitrary code on the affected server.
    confidence_band: high
cves:
  - id: CVE-2024-29837
    cvss: 8.8
    epss: 0.00511
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3349
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Octopus Deploy Server to resolve CVE-2024-29837.
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability is standard for this CVE.
  mitigation_plan:
    - priority: immediate
      action: Isolate Octopus Deploy management interface from the public internet.
      owner: IT Operations
      addresses: CVE-2024-29837
      evidence: General mitigation for RCE in CI/CD orchestration tools.
---

Octopus Deploy Server contains a security vulnerability that permits a remote, unauthenticated attacker to achieve remote code execution (RCE) on the host system. This vulnerability, tracked as CVE-2024-29837, affects the core server component, which is widely used for automated software deployment and release management. Successful exploitation allows an adversary to gain full control over the application instance, enabling them to steal sensitive deployment credentials, modify application configurations, or pivot into connected infrastructure environments. Defenders should prioritize patching, as this vulnerability provides a direct pathway for full system compromise of build and deployment pipelines.

## Impact

Successful exploitation of this vulnerability leads to full remote code execution on the Octopus Deploy Server. Given the role of this software in managing CI/CD pipelines, a compromise allows an attacker to inject malicious code into downstream software releases, exfiltrate API keys for cloud environments, and gain unauthorized access to managed target infrastructure. Organizations using Octopus Deploy as a central deployment hub are at high risk of supply chain compromise if their orchestration server is breached.

## Recommendation

Prioritize patching all internet-facing and internal Octopus Deploy Server instances to the vendor-provided security update.

* Patch CVE-2024-29837 on all Octopus Deploy Server instances immediately.
* Audit deployment logs for unusual processes spawned by the Octopus Deploy service account or service binary.
* Restrict network access to the Octopus Deploy web interface to authorized management subnets only.
