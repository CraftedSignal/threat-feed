---
title: Jinja Injection Vulnerability in Ansible Automation Controller
slug: 2026-09-ansible-jinja-injection
description: A flaw in the sanitize_jinja() function of Ansible Automation Controller allows low-privileged users to execute arbitrary commands and disclose sensitive credentials via injected Jinja templates.
date: "2026-09-23T20:44:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:ansible_automation_controller:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - jinja-injection
  - ansible
vendors:
  - Red Hat
products:
  - Ansible Automation Controller
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This enables execution of arbitrary commands in the execution environment (bypassing an administrator's AD_HOC_COMMANDS module allowlist).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This enables execution of arbitrary commands... and disclosure of secrets belonging to credentials the attacker cannot read... across the credential access-control boundary.
    confidence_band: high
cves:
  - id: CVE-2026-84714
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84714
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Ansible Automation Controller systems to the version resolving CVE-2026-84714.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-84714 requires remediation.
  enrichment_needed:
    - item: Exploitation attempts in web access logs or controller audit logs.
      owner: SOC
      reason: Establish baselines for legitimate Jinja usage to identify anomalies.
      evidence: Lack of specific IOCs in report.
  mitigation_plan:
    - priority: immediate
      action: Identify and audit users with permissions to modify ad-hoc command parameters or inventory host names.
      owner: SOC
      addresses: CVE-2026-84714
      evidence: Source identifies these as the specific vulnerable fields.
---

CVE-2026-84714 describes a critical input-validation vulnerability in the sanitize_jinja() function within Ansible Automation Controller. The function utilizes regular expressions to filter user-supplied Jinja code but fails to account for nested expressions, as the patterns terminate at the first encountered '}' or '%' character. Consequently, attackers can bypass these filters using nested Jinja syntax, such as empty dictionaries, which remain executable by ansible-core within the execution environment. This flaw affects multiple critical launch-time fields, including ad-hoc command module arguments, machine credential parameters (username, become_method, become_user), and inventory host names. A low-privileged user can leverage this vulnerability to bypass administrative module allowlists for ad-hoc commands, execute arbitrary code within the execution environment, and exfiltrate secrets from co-attached credentials by templating environment variables. The vulnerability allows for an escalation of privilege across defined credential access-control boundaries.

## Impact

Successful exploitation allows low-privileged users to achieve arbitrary command execution within the Ansible execution environment and gain unauthorized access to sensitive credentials. This poses a significant risk to organizations relying on Ansible Automation Controller for secure infrastructure orchestration, as it permits attackers to bypass established security policies, such as ad-hoc command module allowlists, and exfiltrate credentials they would not normally be authorized to access.

## Recommendation

1. Monitor for and apply vendor-supplied patches for Ansible Automation Controller to address CVE-2026-84714.
2. Review and audit existing Jinja templates used in inventory host names and credential parameters for unauthorized nested expressions.
3. Restrict permissions for users authorized to define ad-hoc command parameters or inventory settings within the Automation Controller interface.
4. Implement strict monitoring on the execution environment to detect unexpected command patterns or unauthorized access to credential-related environment variables.
