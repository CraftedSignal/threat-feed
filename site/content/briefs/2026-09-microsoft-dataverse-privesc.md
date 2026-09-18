---
title: Microsoft Dataverse Privilege Escalation Vulnerability
slug: 2026-09-microsoft-dataverse-privesc
description: A vulnerability in Microsoft Dataverse identified as CVE-2024-38064 allows a remote, unauthenticated attacker to escalate privileges and potentially gain administrative access to the service.
date: "2026-09-18T19:46:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cloud-security
  - vulnerability
  - high-confidence-source
vendors:
  - Microsoft
products:
  - Dataverse
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in Microsoft Dataverse allows a remote, unauthenticated attacker to escalate their privileges within the service.
    confidence_band: high
cves:
  - id: CVE-2024-38064
    cvss: 7.5
    epss: 0.02195
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3459
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38064
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review Power Platform and Dataverse audit logs for anomalous administrative behavior.
      owner: SOC
      due: 24h
      evidence: Source reporting of privilege escalation impact.
  mitigation_plan:
    - priority: immediate
      action: Verify current patch status of Dataverse instances via the Microsoft 365 admin center.
      owner: IT Operations
      addresses: CVE-2024-38064
      evidence: Vendor security advisory.
---

Microsoft has disclosed a security vulnerability affecting Microsoft Dataverse, a cloud-based service used to store and manage data for business applications. The vulnerability, tracked as CVE-2024-38064, allows a remote, unauthenticated attacker to perform a privilege escalation attack. Successful exploitation could grant an attacker unauthorized administrative capabilities within the Dataverse environment, leading to data exposure, unauthorized modification, or complete compromise of the affected service instances. Organizations utilizing Dataverse should review their security configurations and monitor for unauthorized administrative actions. As this is a cloud-native vulnerability, mitigation is primarily managed through vendor-applied patches and platform-level security updates.

## Impact

The vulnerability poses a high risk to organizations relying on Microsoft Dataverse for business-critical data. If exploited, an attacker could bypass authentication controls to obtain elevated permissions, potentially resulting in full administrative control over Dataverse instances. This impact includes the potential for unauthorized access to sensitive corporate data, manipulation of business logic, and disruption of integrated services that rely on Dataverse for backend storage and operations.

## Recommendation

Prioritize the following actions for security and identity teams:

- Review administrative activity logs in the Microsoft 365 or Power Platform admin centers for unusual activity.
- Implement the principle of least privilege for all Dataverse service accounts and users.
- Ensure that Conditional Access policies are strictly enforced for all administrative access to the Power Platform.
- Monitor vendor security bulletins for further guidance on verifying instance patching for CVE-2024-38064.
