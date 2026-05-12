---
title: Heym Authorization Bypass Vulnerability CVE-2026-45226
slug: 2026-05-heym-auth-bypass
description: Heym before 0.0.21 contains an authorization bypass vulnerability (CVE-2026-45226) that allows authenticated users to execute arbitrary workflows by referencing victim workflow UUIDs, leading to exposure of outputs and unintended side effects.
date: "2026-05-12T22:18:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - workflow-execution
  - cve
vendors:
  - Heym
products:
  - Heym
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-45226
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45226
  - CVE-2026-45226
rules:
  - title: Detect Heym Workflow Execution with Subworkflow UUID
    description: Detects Heym workflow executions that include a subworkflow UUID, potentially indicating an authorization bypass attempt (CVE-2026-45226).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect Heym Malicious Workflow Creation via API
    description: Detects the creation of potentially malicious workflows by monitoring API requests containing subworkflow UUIDs (CVE-2026-45226).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Heym before version 0.0.21 is vulnerable to an authorization bypass, as identified by CVE-2026-45226. This flaw allows authenticated users to bypass access controls and execute arbitrary workflows. The vulnerability stems from a lack of proper access validation when referencing workflow UUIDs. Attackers can exploit this by creating malicious workflows that reference UUIDs of victim workflows, enabling them to load and execute these workflows under attacker-controlled execution paths. This leads to potential exposure of sensitive victim workflow outputs and unintended triggering of workflow nodes with adverse side effects. This vulnerability poses a significant risk to the confidentiality and integrity of workflows within Heym environments.

## Attack Chain

1. An attacker authenticates to a Heym instance.
2. The attacker identifies a victim workflow and obtains its UUID.
3. The attacker creates a new workflow containing either an "execute" node or an "agent subWorkflowId".
4. Within the "execute" node or "agent subWorkflowId", the attacker references the victim workflow's UUID.
5. The attacker executes their newly crafted workflow.
6. Due to the authorization bypass, the Heym system loads and executes the victim workflow under the attacker's execution context.
7. The attacker gains access to the victim workflow's outputs.
8. Workflow nodes within the victim workflow are triggered with unintended side effects, potentially causing further damage.

## Impact

Successful exploitation of CVE-2026-45226 allows an attacker to execute arbitrary workflows without proper authorization. This can lead to the exposure of sensitive data contained within the victim workflows, as well as the unintended triggering of workflow nodes, potentially causing data corruption or other malicious side effects. The vulnerability affects Heym instances before version 0.0.21 and poses a risk to the confidentiality, integrity, and availability of workflow data.

## Recommendation

*   Upgrade Heym to version 0.0.21 or later to patch CVE-2026-45226.
*   Deploy the Sigma rule "Detect Heym Workflow Execution with Subworkflow UUID" to identify potentially malicious workflow executions.
*   Monitor Heym logs for unauthorized workflow executions referencing unusual or suspicious workflow UUIDs.
