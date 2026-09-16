---
title: Authorization Bypass in Rundeck Project Archive Import
slug: 2026-09-rundeck-auth-bypass
description: Rundeck versions through 6.2.1 contain an authorization vulnerability in the project archive import endpoint allowing low-privileged users to overwrite sensitive project configuration files.
date: "2026-09-16T21:55:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pagerduty:rundeck:*:*:*:*:*:*:*:*
vendors:
  - PagerDuty
products:
  - Rundeck (<= 6.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker with only the import action can replace project configuration files including security-relevant settings like node executors and SSH key paths that affect job execution.
    confidence_band: high
cves:
  - id: CVE-2026-92763
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92763
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Rundeck to version > 6.2.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92763 remediation
  hunt_leads:
    - lead: Audit project import logs for unauthorized parameter usage
      technique_id: T1068
      data_needed:
        - Rundeck web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Authorization bypass via importConfig and importNodesSources parameters
  mitigation_plan:
    - priority: immediate
      action: Restrict 'import' permission for non-administrative users
      owner: IT Operations
      addresses: CVE-2026-92763
      evidence: Vulnerability allows privilege escalation for users with import action
---

Rundeck versions 6.2.1 and earlier are vulnerable to an authorization bypass flaw (CVE-2026-92763) within the project archive import functionality. The vulnerability specifically affects the handling of the 'importConfig' and 'importNodesSources' parameters. An attacker holding only basic 'import' permissions - which are intended for managing project archives - can leverage these parameters to manipulate sensitive configuration files. By exploiting this flaw, an attacker can modify security-critical settings such as node executor definitions and SSH key paths. This manipulation allows for the redirection of job execution, potentially enabling the attacker to execute arbitrary code or commands in the context of the Rundeck service or target managed nodes. This flaw is particularly significant as it effectively escalates the privileges of an import-authorized user to those of a project administrator.

## Impact

Successful exploitation allows a user with restricted import permissions to reconfigure project settings, leading to unauthorized code execution, credential exfiltration via modified SSH key paths, or full takeover of project-level automation tasks. This vulnerability affects all environments running Rundeck version 6.2.1 or older that utilize the project archive feature.

## Recommendation

* Upgrade Rundeck to a patched version beyond 6.2.1 immediately to remediate CVE-2026-92763.
* Audit the access control policies to identify and restrict users assigned the 'import' permission until the patch is applied.
* Review Rundeck project configuration history and audit logs for unexpected modifications to 'project.properties' or node source configurations.
