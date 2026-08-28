---
title: Remote Code Execution in BISHENG Workflow API
slug: 2026-08-bisheng-rce
description: Authenticated users can achieve remote code execution in BISHENG versions prior to 2.6.0 by submitting crafted Python payloads to the /api/v1/workflow/run_once endpoint.
date: "2026-08-28T21:38:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bisheng:bisheng:*:*:*:*:*:*:*:*
vendors:
  - BISHENG
products:
  - BISHENG (< 2.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: BISHENG before 2.6.0 contains a remote code execution vulnerability in the workflow run_once endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can submit crafted Code node definitions to the POST /api/v1/workflow/run_once endpoint, which executes them with exec() without sandboxing.
    confidence_band: high
cves:
  - id: CVE-2026-82278
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82278
rules:
  - title: Detects CVE-2026-82278 Exploitation - Remote Code Execution via Workflow API
    description: Detects attempts to execute arbitrary code by POSTing to the workflow run_once endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade BISHENG to version 2.6.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source states BISHENG before 2.6.0 is vulnerable
  hunt_leads:
    - lead: Search web logs for POST requests to /api/v1/workflow/run_once
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies this as the vulnerable endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade BISHENG to 2.6.0
      owner: IT Operations
      addresses: CVE-2026-82278
      evidence: NVD vulnerability disclosure
---

BISHENG versions prior to 2.6.0 contain a critical remote code execution vulnerability (CVE-2026-82278) located within the workflow run_once endpoint. An authenticated attacker can exploit this vulnerability by submitting a maliciously crafted Code node definition to the POST /api/v1/workflow/run_once endpoint. The application processes this payload using the Python exec() function without adequate sandboxing or input validation. Successful exploitation grants the attacker the ability to execute arbitrary Python code within the context of the application, leading to unauthorized access to the underlying filesystem, sensitive stored credentials, and internal network resources. Defenders should prioritize patching to version 2.6.0 or later to remediate the lack of process isolation.

## Impact

Successful exploitation of CVE-2026-82278 results in complete loss of confidentiality, integrity, and availability for the BISHENG instance. Impact includes unauthorized access to system-level files, exfiltration of stored credentials used for workflow integrations, and potential lateral movement into the organization's internal network via the application's privileged network access.

## Recommendation

- Upgrade BISHENG instances to version 2.6.0 or later immediately to resolve CVE-2026-82278.
- Audit logs for authenticated users accessing /api/v1/workflow/run_once to identify potential exploitation attempts.
- Restrict access to the BISHENG API to authorized users and networks via firewall or network access control lists.
- Implement monitoring for the exec() function or unusual child process spawns from the BISHENG application process if feasible within the environment.
