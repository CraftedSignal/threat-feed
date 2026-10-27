---
brief_id: brief-2026-10-27-airflow-ssh-injection
event_id: brief-2026-10-27-airflow-ssh-injection
revision: 1
activity_at: "2026-10-27T00:32:41Z"
title: 'Apache Airflow SSH provider: Command injection in SSHRemoteJobOperator (CVE-2026-111422)'
slug: 2026-10-airflow-ssh-injection
description: A command injection vulnerability in the Apache Airflow SSH provider allows attackers to achieve remote code execution on SSH hosts by injecting shell syntax into the environment parameter of SSHRemoteJobOperator.
date: "2026-10-27T00:32:41Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; vulnerability details confirmed by upstream provider.
cpes:
  - cpe:2.3:a:apache:airflow_ssh_provider:*:*:*:*:*:*:*:*
tags:
  - airflow
  - command-injection
  - rce
vendors:
  - Apache
products:
  - Apache Airflow SSH provider (4.3.0 - 7.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: SSHRemoteJobOperator quoted the values of its templated environment parameter only once, although they are placed inside an already-quoted wrapper script, so shell syntax such as $(...) in a value was executed on the remote SSH host.
    confidence_band: high
cves:
  - id: CVE-2026-111422
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade apache-airflow-providers-ssh to 7.0.1 or later.
      owner: IT Operations
      due: 72h
      evidence: The vendor has released version 7.0.1 to address the improper quoting vulnerability.
  hunt_leads:
    - lead: Identify DAGs utilizing SSHRemoteJobOperator that dynamically populate the environment parameter from user-controllable input or params.
      technique_id: T1059.004
      data_needed:
        - Airflow DAG definition source code
        - Audit logs for DAG parameter inputs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs when trigger-time input such as params is passed into the environment parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Apache Airflow SSH provider components to version 7.0.1.
      owner: IT Operations
      addresses: CVE-2026-111422
      evidence: Source notes fixed version as 7.0.1.
---

Apache Airflow SSH provider versions 4.3.0 through 7.0.0 are vulnerable to command injection via the `SSHRemoteJobOperator`. The vulnerability stems from improper quoting of the templated `environment` parameter. Because the values are placed within an already-quoted wrapper script without sufficient escaping, an attacker providing malicious input (such as command substitution syntax `$(...)`) via DAG parameters can cause the remote SSH host to execute arbitrary shell commands.

## Impact

Successful exploitation allows for remote code execution on the target host defined in the SSH connection. This may lead to unauthorized access to the target infrastructure, privilege escalation, or lateral movement from the Airflow environment to the SSH-connected system.

## Recommendation

* Upgrade the `apache-airflow-providers-ssh` package to version 7.0.1 or later.
* Audit existing DAGs using `SSHRemoteJobOperator` to ensure that input passed into the `environment` parameter is strictly validated and does not contain shell metacharacters or command substitution sequences.
