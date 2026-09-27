---
title: Missing Authorization Vulnerability in Coolify
slug: 2026-09-coolify-missing-auth
description: Coolify versions 4.1.2 and prior contain a missing authorization vulnerability in the Route-Level Middleware component, allowing remote attackers to perform unauthorized resource updates.
date: "2026-09-27T03:03:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coollabs:coolify:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - authentication-bypass
vendors:
  - Coollabs
products:
  - Coolify (<= 4.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-100744
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100744
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Coolify to version 4.2.0
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 4.2.0 is sufficient to fix this issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Coolify to 4.2.0
      owner: IT Operations
      addresses: CVE-2026-100744
      evidence: Upgrading to version 4.2.0 is sufficient to fix this issue.
---

Coolify versions up to 4.1.2 are susceptible to a security flaw identified as CVE-2026-100744, residing within the Route-Level Middleware component. Specifically, the vulnerability exists in the `app/Http/Middleware/CanUpdateResource.php` file, which fails to properly enforce authorization checks when handling requests. This flaw enables a remote, unauthenticated attacker to manipulate resource access, potentially resulting in unauthorized modifications to infrastructure or application configurations managed by Coolify. Publicly available exploit material indicates that this vulnerability is actively tracked, increasing the risk of exploitation. Defenders should prioritize updating to Coolify version 4.2.0, which includes the necessary patch (commit 39ae16de4248075de8c08f3259114e064b20d52d) to resolve the missing authorization logic.

## Impact

Successful exploitation allows remote actors to bypass security controls and perform unauthorized operations within the Coolify dashboard. This can lead to full compromise of managed infrastructure, unauthorized deployment of malicious services, or the manipulation of application settings, posing a critical risk to environments relying on Coolify for container orchestration and self-hosted application management.

## Recommendation

* Upgrade all instances of Coolify to version 4.2.0 or later to remediate CVE-2026-100744.
* Audit application logs for abnormal requests directed at resource-management endpoints, particularly those attempting to trigger update middleware.
* Review access control configurations for all managed resources to ensure unintended modifications have not been performed.
