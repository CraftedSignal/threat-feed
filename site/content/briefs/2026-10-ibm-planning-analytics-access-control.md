---
title: Improper Functional Level Access Control in IBM Planning Analytics
slug: 2026-10-ibm-planning-analytics-access-control
description: IBM Planning Analytics versions 2.0 and 2.1 are vulnerable to an improper functional level access control flaw, enabling remote authenticated attackers to delete folders and applications belonging to other users.
date: "2026-10-13T00:33:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:ibm:planning_analytics:2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:planning_analytics:2.1:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Planning Analytics (2.0, 2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM Planning Analytics versions 2.0 and 2.1 could allow a remote authenticated attacker to delete folders and applications belonging to other users due to improper functional level access control.
    confidence_band: high
cves:
  - id: CVE-2026-17475
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17475
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply vendor patches for IBM Planning Analytics 2.0 and 2.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17475 disclosure
  hunt_leads:
    - lead: Anomalous folder or application deletion requests from non-administrative users
      technique_id: T1068
      data_needed:
        - Application-level access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Improper functional level access control allows unauthorized deletion
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version of IBM Planning Analytics
      owner: IT Operations
      addresses: CVE-2026-17475
      evidence: NVD vulnerability disclosure
---

IBM Planning Analytics versions 2.0 and 2.1 contain a critical security vulnerability characterized as an improper functional level access control flaw. This vulnerability resides within the application's authorization logic, which fails to correctly validate the permissions of an authenticated user before executing folder or application deletion requests. An authenticated attacker, who has already gained access to the platform, can leverage this vulnerability to perform unauthorized deletion of resources owned by other users. This issue poses a significant risk to data integrity and availability, as attackers can maliciously destroy critical business applications or organizational folders. The scope is limited to authenticated users, meaning the primary vector involves compromised or malicious insider accounts operating within the Planning Analytics environment.

## Impact

Successful exploitation of this vulnerability results in unauthorized data destruction. By deleting folders and applications belonging to other users, an attacker can cause significant disruption to business operations and loss of intellectual property or analytical data. The vulnerability affects all deployments of IBM Planning Analytics versions 2.0 and 2.1 regardless of the underlying operating system. Organizations relying on this platform for critical planning and financial analysis are at risk of data loss and potential service degradation if a malicious actor targets their shared directory structures.

## Recommendation

Prioritize the implementation of the vendor-supplied security patches for the affected Planning Analytics installations. Given that this vulnerability requires an authenticated session, enhance session monitoring and implement strict role-based access control (RBAC) reviews to ensure that users have only the minimum necessary privileges for their roles. Conduct a thorough audit of application logs to identify unauthorized deletion attempts or anomalous administrative activity originating from low-privilege accounts. 

- Apply the latest security updates provided by IBM for Planning Analytics 2.0 and 2.1 to resolve the improper functional level access control vulnerability (CVE-2026-17475).
- Review and restrict administrative permissions to ensure that only authorized accounts can perform folder and application management tasks.
- Monitor application access logs for repeated `DELETE` or `REMOVE` requests targeting resources owned by accounts other than the active session user.
