---
brief_id: brief-2026-10-31-showdoc-code-injection
event_id: brief-2026-10-31-showdoc-code-injection
revision: 1
activity_at: "2026-10-31T22:05:36Z"
title: 'ShowDoc: Remote code execution in Mock feature (CVE-2026-120203)'
slug: 2026-10-showdoc-code-injection
description: ShowDoc versions 2.8.14 through 3.9.5 are vulnerable to authenticated remote code execution via a code injection flaw in the Mock feature's template processing.
date: "2026-10-31T22:05:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified against NVD
cpes:
  - cpe:2.3:a:showdoc:showdoc:*:*:*:*:*:*:*:*
tags:
  - webserver
  - rce
  - injection
vendors:
  - ShowDoc
products:
  - ShowDoc (2.8.14 <= version < 3.9.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: Authenticated users can execute shell commands through mockjs templates.
    confidence_band: high
cves:
  - id: CVE-2026-120203
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120203
rules:
  - title: Detect CVE-2026-120203 Exploitation - Suspicious Mock Template Submission
    description: Detects potential CVE-2026-120203 exploitation by monitoring HTTP POST requests to the MockController add endpoint containing suspicious characters often associated with shell injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch ShowDoc to version 3.9.6 or later
      owner: IT Operations
      due: 24h
      evidence: ShowDoc version 2.8.14 before 3.9.6 contains a code injection vulnerability
  hunt_leads:
    - lead: Search web logs for POST requests to /MockController/add or /MockController/infoByKey followed by unusual system command activity
      technique_id: T1059.003
      data_needed:
        - webserver_access_logs
        - os_process_creation_logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers store a template via MockController::add... then trigger it through MockController::infoByKey to run commands
  mitigation_plan:
    - priority: immediate
      action: Upgrade ShowDoc to 3.9.6
      owner: IT Operations
      addresses: CVE-2026-120203
      evidence: Upgrade ShowDoc to version 3.9.6 or later
---

ShowDoc 2.8.14 through 3.9.5 contains a code injection vulnerability in its Mock feature, tracked as CVE-2026-120203. Authenticated users can inject malicious shell commands into mockjs templates via the MockController::add endpoint. When these templates are subsequently processed via MockController::infoByKey, the application uses eval() to execute the embedded code, leading to command execution with root privileges in default Docker deployments.

## Attack Chain
1. Attacker authenticates to the ShowDoc application.
2. Attacker crafts a malicious mockjs template containing shell commands.
3. Attacker submits the payload via the MockController::add endpoint.
4. The malicious template is stored in the application database.
5. Attacker triggers execution by accessing the MockController::infoByKey endpoint.
6. The application processes the template using eval(), executing the payload as root.

## Impact
Successful exploitation allows for arbitrary command execution with root privileges when the application is running in the official Docker environment.

## Recommendation
Upgrade ShowDoc to version 3.9.6 or later to address the vulnerable Mock feature.
