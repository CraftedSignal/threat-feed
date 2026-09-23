---
title: Credential Exposure in Red Hat Ansible Automation Platform via CVE-2026-84499
slug: 2026-09-ansible-controller-vuln
description: A vulnerability in Red Hat Ansible Automation Platform's automation-controller allows a low-privileged JobTemplate Admin to exfiltrate plaintext passwords from survey questions via error message injection.
date: "2026-09-23T20:44:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:red_hat:ansible_automation_platform:*:*:*:*:*:*:*:*
tags:
  - credential-theft
  - vulnerability
  - web-application
vendors:
  - Red Hat
products:
  - Ansible Automation Platform (automation-controller)
cves:
  - id: CVE-2026-84499
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84499
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Monitor automation-controller logs for error messages related to survey length validation
      owner: SOC
      due: 24h
      evidence: Source states error message contains plaintext password
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ansible Automation Platform to the version addressing CVE-2026-84499
      owner: IT Operations
      addresses: CVE-2026-84499
      evidence: Source identifies vulnerability in automation-controller
  gaps:
    - Need exact fixed version number from Red Hat
---

CVE-2026-84499 is a security vulnerability in the Red Hat Ansible Automation Platform automation-controller where sensitive survey data, specifically password-type fields, are improperly handled during validation. These fields are typically stored encrypted and intended to be write-only, masking their value when viewed via the UI or API. However, when a user with the JobTemplate Admin role modifies a schedule or workflow job template node to use a stricter survey length specification, the automation-controller triggers a revalidation process. During this process, the application inadvertently decrypts the stored password and echoes the plaintext value directly into the HTTP response body as part of a minimum/maximum length validation error message. This allows a malicious or compromised administrative user to recover plaintext credentials belonging to higher-privileged users, leading to potential privilege escalation or lateral movement across the infrastructure managed by Ansible.

## Impact

Successful exploitation results in the exposure of plaintext credentials stored within Ansible surveys. This impacts organizations using the platform for automated secret management or infrastructure orchestration, potentially leading to unauthorized access to downstream systems and administrative takeover of the automation-controller environment.

## Recommendation

- Upgrade Red Hat Ansible Automation Platform to the patched version once released by Red Hat to resolve CVE-2026-84499.
- Audit logs for the automation-controller for frequent or suspicious modifications to job template survey specifications by low-privileged administrators.
- Restrict the 'JobTemplate Admin' role in Ansible environments to highly trusted personnel until the patch is applied.
