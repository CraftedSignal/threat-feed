---
brief_id: brief-2026-10-29-olivetin-rce
event_id: brief-2026-10-29-olivetin-rce
revision: 1
activity_at: "2026-10-29T03:49:38Z"
title: 'OliveTin: Unauthenticated Remote Code Execution (CVE-2026-30225)'
slug: 2026-10-olivetin-rce
description: OliveTin versions prior to 3000.11.1 are vulnerable to unauthenticated remote code execution via insecure guest configurations and lack of input validation for action arguments.
date: "2026-10-29T03:49:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:olivetin:olivetin:*:*:*:*:*:*:*:*
vendors:
  - OliveTin
products:
  - OliveTin (< 3000.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in OliveTin 3000.10.0 via guest default config allowing shell injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: 'Any action whose shell: template interpolates such an argument is a shell-injection sink.'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Verified against OliveTin 3000.10.0 running as root, where it yields an unauthenticated root shell.
    confidence_band: high
cves:
  - id: CVE-2026-30225
    cvss: 5.3
    epss: 0.00431
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACKERKING24-CVE-2026-30225-OLIVETIN-RCE
  - https://github.com/OliveTin/OliveTin
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACKERKING24-CVE-2026-30225-OLIVETIN-RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect OliveTin Unauthenticated Action Execution
    description: Detects HTTP POST requests to OliveTin action endpoints originating from unauthenticated guest sessions or suspicious shell injection syntax in query parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all instances of OliveTin within the network and verify versioning
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects OliveTin versions < 3000.11.1
  hunt_leads:
    - lead: Identify unauthenticated access to the OliveTin API port (default 1337)
      technique_id: T1190
      data_needed:
        - Firewall or NetFlow logs monitoring connections to port 1337
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Network access to the OliveTin API (often 127.0.0.1:1337)
  mitigation_plan:
    - priority: immediate
      action: Upgrade OliveTin to 3000.11.1 or later
      owner: IT Operations
      addresses: CVE-2026-30225
      evidence: Fixed in 3000.11.1
---

OliveTin versions below 3000.11.1 contain multiple vulnerabilities that facilitate unauthenticated remote code execution (RCE). The primary vectors involve insecure default configurations where guest users are granted `exec` permissions, combined with a lack of input validation in argument types (e.g., `password`, `raw_string_multiline`). These arguments are interpolated directly into shell templates, allowing for shell injection. Additionally, CVE-2026-30225 identifies an ACL bypass in the `RestartAction` function, where the application fails to maintain the authenticated context, causing actions to be re-executed with guest privileges.

## Attack Chain
1. Attacker performs reconnaissance to identify exposed OliveTin API endpoints (default port 1337).
2. Attacker confirms the target is running with default guest permissions (`authRequireGuestsToLogin: false`).
3. Attacker maps available actions and argument structures via the API.
4. Attacker identifies an action that utilizes an unvalidated argument type in a `shell:` template.
5. Attacker crafts a payload to escape the shell command argument (e.g., using single quotes and command chaining).
6. Attacker sends an HTTP POST request to `StartActionAndWait` containing the malicious payload.
7. OliveTin processes the command as the application user (often `root`), executing the attacker's payload.
8. The output of the command is returned to the attacker in the response log.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary commands with the privileges of the OliveTin process. If OliveTin is running as `root`, this results in full system compromise.

## Recommendation
1. Patch immediately: Upgrade OliveTin to version 3000.11.1 or later.
2. Harden configuration: Set `authRequireGuestsToLogin: true` in `config.yaml` and restrict `exec` permissions for guest and default roles.
3. Principle of Least Privilege: Ensure OliveTin runs under a dedicated, low-privilege service account rather than `root`.
4. Input Validation: Audit existing action definitions and remove or heavily restrict reliance on `shell` templates, preferring `exec` arguments where possible.
