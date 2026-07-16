---
title: Authorization Bypass in Axelor Open Platform (CVE-2026-63085)
slug: 2026-07-axelor-privilege-escalation
description: An authorization bypass vulnerability, CVE-2026-63085, in Axelor Open Platform versions 8.x prior to 8.2.2 allows authenticated non-admin users to exploit unenforced field restrictions during nested relational save operations to modify sensitive user record fields like roles and groups, thereby escalating privileges to administrative levels.
date: "2026-07-16T17:20:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - authorization-bypass
vendors:
  - Axelor
products:
  - Axelor Open Platform (< 8.2.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated non-admin users to escalate privileges by exploiting unenforced field restrictions on nested relational save operations. Attackers can modify sensitive User record fields such as roles and group by submitting changes through a related entity's save path, bypassing the USER_RESTRICTED_FIELDS control and causing the JPA persistence layer to flush attacker-supplied admin role and group assignments on commit.
    confidence_band: high
cves:
  - id: CVE-2026-63085
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63085
---

Axelor Open Platform versions 8.x, specifically those prior to 8.2.2, are affected by an authorization bypass vulnerability identified as CVE-2026-63085. This critical flaw allows an authenticated non-administrative user to achieve privilege escalation. The vulnerability stems from unenforced field restrictions during nested relational save operations. By leveraging a related entity's save path, attackers can modify sensitive user record fields, such as assigned roles and groups, effectively bypassing the `USER_RESTRICTED_FIELDS` control. The Java Persistence API (JPA) layer then commits these attacker-supplied administrative role and group assignments. This critical vulnerability, with a CVSS v3.1 Base Score of 8.8, poses a significant risk as it enables unauthorized users to gain full administrative control over the platform, leading to potential data manipulation, system compromise, or further attacks. Defenders must prioritize patching to prevent unauthorized privilege escalation within their Axelor deployments.

## Attack Chain

1. An authenticated user with non-admin privileges successfully logs into the Axelor Open Platform.
2. The attacker identifies a specific related entity's save path that is vulnerable to unenforced field restrictions during nested relational save operations.
3. The attacker crafts a malicious request to modify their own user record's sensitive fields, such as `roles` or `groups`, by including administrative assignments.
4. The crafted request is submitted through the identified vulnerable related entity's save path.
5. Due to the authorization bypass, the platform's `USER_RESTRICTED_FIELDS` control is not enforced for this specific nested relational save operation.
6. The Java Persistence API (JPA) persistence layer processes the request and flushes the attacker-supplied administrative role and group assignments on commit.
7. The attacker's user account is successfully granted administrative privileges within the Axelor Open Platform.
8. The attacker now has full administrative control over the platform, enabling further malicious activities.

## Impact

Successful exploitation of CVE-2026-63085 grants an authenticated non-administrative user full administrative privileges within the Axelor Open Platform. This can lead to a complete compromise of the system, allowing the attacker to access, modify, or delete any data, disrupt business operations, install malicious software, or establish persistent access. Organizations using affected versions face severe risks, including data breaches, operational downtime, and reputational damage. The lack of proper authorization enforcement means that a standard user can elevate themselves to the highest level of control, bypassing all security controls designed to segregate duties, potentially leading to unauthorized data exposure or manipulation.

## Recommendation

* **Patch CVE-2026-63085**: Immediately upgrade all Axelor Open Platform installations to version 8.2.2 or newer to mitigate the authorization bypass vulnerability.
* **Monitor application logs**: Implement detailed logging and review Axelor application logs for unusual changes to user roles or group assignments, especially those initiated by non-administrative accounts, to detect potential exploitation attempts.
* **Implement strong access controls**: Regularly audit user permissions and ensure the principle of least privilege is strictly enforced for all users within the Axelor Open Platform.
