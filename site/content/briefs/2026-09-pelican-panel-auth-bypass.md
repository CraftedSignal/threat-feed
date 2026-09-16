---
title: Authorization Bypass in Pelican Panel via Livewire State Manipulation
slug: 2026-09-pelican-panel-auth-bypass
description: Pelican Panel versions before 1.0.0-beta35 fail to enforce server-side write permissions, allowing attackers with read-only access to achieve arbitrary command execution via manipulated Livewire state updates.
date: "2026-09-16T21:55:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pelican_panel:pelican_panel:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - authorization-bypass
  - cve-2026-92762
vendors:
  - Pelican Panel
products:
  - Pelican Panel (< 1.0.0-beta35)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with startup.read permission can craft Livewire state updates to invoke afterStateUpdated callbacks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Modify startup commands, docker images, and variables to execute arbitrary commands in the container.
    confidence_band: high
cves:
  - id: CVE-2026-92762
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92762
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Pelican Panel to version 1.0.0-beta35 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92762 remediation
  mitigation_plan:
    - priority: immediate
      action: Review user permissions and restrict startup.read access
      owner: Security Operations
      addresses: CVE-2026-92762
      evidence: Source material describes authorization bypass via read permissions
---

Pelican Panel versions prior to 1.0.0-beta35 contain an authorization bypass vulnerability (CVE-2026-92762) affecting startup configuration management. The application erroneously relies on client-side form controls to restrict write access to startup settings. An attacker possessing only 'startup.read' permissions can exploit this by crafting malicious Livewire state updates. These updates trigger 'afterStateUpdated' callbacks, which bypass intended authorization checks. By invoking these callbacks, the attacker can modify critical server settings, including startup commands, Docker images, and environment variables. This manipulation allows for the injection of malicious payloads that result in arbitrary command execution within the application container. The vulnerability highlights the danger of relying on UI-level restrictions for security-sensitive administrative operations.

## Impact

Successful exploitation of this vulnerability allows an attacker with limited read-only permissions to gain full control over the container environment managed by Pelican Panel. This enables arbitrary code execution, potential data exfiltration from the container, and lateral movement within the host infrastructure if container isolation is insufficient.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Upgrade all Pelican Panel instances to version 1.0.0-beta35 or later immediately to patch CVE-2026-92762.
- Audit user permission sets within Pelican Panel to ensure that the 'startup.read' permission is limited to the minimum number of users required.
- Review and harden Docker container security profiles (e.g., using AppArmor or Seccomp) to limit the impact of potential arbitrary command execution within the container runtime.
- Implement monitoring on administrative API endpoints related to startup configurations and Livewire state management to detect abnormal update patterns.
