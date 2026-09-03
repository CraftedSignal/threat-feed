---
title: Kill Bill Administrative Endpoint Permission Bypass
slug: 2026-09-kill-bill-permission-bypass
description: Kill Bill versions 0.24.21 and earlier contain a security misconfiguration where authenticated users with minimal account:read privileges can perform unauthorized administrative actions.
date: "2026-09-03T17:22:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kill_bill:kill_bill:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - privilege-escalation
  - access-control
vendors:
  - Kill Bill
products:
  - Kill Bill (<= 0.24.21)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users with minimal account:read permissions can read internal queues, flush server caches, and disable the server by putting the host out of rotation.
    confidence_band: high
cves:
  - id: CVE-2026-85213
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85213
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review access logs for unauthorized attempts to reach /admin/ endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-85213 vulnerability in AdminResource endpoints
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kill Bill to the patched version as soon as released
      owner: IT Operations
      addresses: CVE-2026-85213
      evidence: NVD vulnerability disclosure
---

Kill Bill versions 0.24.21 and earlier suffer from a critical permission enforcement vulnerability (CVE-2026-85213) within the application's AdminResource endpoints. Security analysis confirms that the system fails to properly validate permissions for several sensitive administrative functions. Specifically, authenticated users who possess only minimal 'account:read' privileges can access restricted endpoints, including 'getQueueEntries', 'invalidatesCache', and 'putOutOfRotation'.

This vulnerability allows low-privileged users to perform actions that should be restricted to administrative roles. The impact ranges from information disclosure of internal system queues and server cache manipulation to a denial-of-service condition where a malicious actor can force the server out of rotation. This exposure poses a significant risk to the availability and integrity of Kill Bill deployments. Defenders should prioritize updating to the patched version of Kill Bill as soon as it becomes available to remediate this bypass of access control mechanisms.

## Impact

Successful exploitation allows authenticated attackers with minimal privileges to perform unauthorized administrative actions, leading to internal information disclosure and service disruption via forced server rotation. This vulnerability affects all Kill Bill deployments running version 0.24.21 or earlier.

## Recommendation

- Monitor web application logs for unauthorized requests targeting the administrative API endpoints identified in this brief.
- Patch Kill Bill to the latest version immediately once the fix for CVE-2026-85213 is released by the vendor.
- Audit existing user permissions and restrict 'account:read' access to the minimum required level until the application is patched.
