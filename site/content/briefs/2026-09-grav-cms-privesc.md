---
title: Privilege Escalation in Grav CMS via Account Blueprint Bypass
slug: 2026-09-grav-cms-privesc
description: Grav CMS versions 2.0.14 through 2.0.24 contain a privilege escalation vulnerability allowing authenticated backend operators to bypass security guards and grant themselves super-admin privileges.
date: "2026-09-26T17:00:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Grav CMS (2.0.14 - 2.0.24)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated backend operator using the flex accounts backend who holds admin.users but not admin.super can therefore grant admin.super to their own account or to a group they belong to and escalate to full super-admin.
    confidence_band: high
cves:
  - id: CVE-2026-100670
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100670
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav CMS to version 2.0.25 or later to resolve CVE-2026-100670.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.0.25, which drops any dotted key whose ancestor path is disabled or marked validate.ignore.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grav CMS to 2.0.25.
      owner: IT Operations
      addresses: CVE-2026-100670
      evidence: Fixed in 2.0.25
---

Grav CMS versions 2.0.14 through 2.0.24 are susceptible to a privilege escalation vulnerability within the handling of group and account blueprints. The vulnerability originates from a flawed security check within `BlueprintSchema::filterArray()`. The system relies on a `security@: admin.super` guard to restrict sensitive account modifications, but this guard is incorrectly resolved based on the specific structure of the input key. 

An authenticated backend operator, possessing at least 'admin.users' permissions, can submit an account update request using a flat dot-notation key (e.g., `access.admin.super`) instead of the expected nested array structure (`access[admin][super]`). This malformed key bypasses the blueprint validation rules, enabling the `FlexObject::update()` method to invoke `setNestedProperty()` with the unauthorized value. By exploiting this, an attacker can modify their own account's access level to include `admin.super`, effectively escalating to full administrative control over the CMS, including plugin/theme installation and file system management. This was remediated in version 2.0.25 by enforcing strict validation on dotted keys.

## Impact

Successful exploitation results in full super-admin account compromise for an authenticated user with limited backend access. Attackers can gain complete control over the CMS configuration, perform unauthorized plugin and theme installations, access the file manager, and manipulate all other user accounts. This represents a significant risk to the integrity and confidentiality of the entire Grav CMS environment.

## Recommendation

* Upgrade Grav CMS to version 2.0.25 or later immediately to apply the patch for CVE-2026-100670.
* Audit administrative account activity logs to identify suspicious modifications to user access levels or unauthorized escalation attempts occurring between September 2026 and the time of patching.
* Restrict access to the backend Flex accounts interface to a strictly controlled set of trusted administrators until the software is updated.
