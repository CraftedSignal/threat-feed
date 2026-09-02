---
title: Information Disclosure Vulnerability in IBM QRadar SIEM
slug: 2026-09-ibm-qradar-disclosure
description: A vulnerability in IBM QRadar SIEM allows a remote, authenticated attacker to gain unauthorized access to sensitive information.
date: "2026-09-02T12:02:49Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:o:huawei:emui:12.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:emui:13.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:emui:14.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:2.1.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:3.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:3.1.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*
  - cpe:2.3:o:huawei:harmonyos:4.2.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - information-disclosure
  - ibm-qradar
vendors:
  - IBM
products:
  - QRadar SIEM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability in IBM QRadar SIEM allows a remote, authenticated attacker to gain unauthorized access to sensitive information, potentially leading to information disclosure.
    confidence_band: med
cves:
  - id: CVE-2024-42037
    cvss: 9.3
    epss: 0.00124
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3139
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review vendor security bulletin and apply available security patches for IBM QRadar SIEM.
      owner: IT Operations
      due: 72h
  hunt_leads:
    - lead: Authenticated users performing unusually high volumes of administrative information queries.
      technique_id: T1592
      data_needed:
        - QRadar system access logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Vulnerability allows authenticated attacker to gain unauthorized access to sensitive information.
  mitigation_plan:
    - priority: medium
      action: Patch IBM QRadar SIEM software.
      owner: IT Operations
      addresses: CVE-2024-42037
---

IBM has disclosed a security vulnerability identified as CVE-2024-42037 affecting IBM QRadar SIEM. The vulnerability permits a remote, authenticated attacker to access sensitive information that should otherwise be restricted. Successful exploitation of this flaw leads to unauthorized information disclosure, potentially exposing configuration details, logs, or system data. This issue highlights the importance of access control verification within the SIEM environment. As of the current advisory, there are no reports of widespread active exploitation, but the impact necessitates prompt patch management to prevent potential reconnaissance activities by authorized users who may attempt to exceed their privileges.

## Impact

The vulnerability allows an authenticated user to bypass intended access controls to retrieve restricted system data. Successful exploitation could compromise the confidentiality of security data managed by the SIEM, affecting organizations that rely on QRadar for sensitive log aggregation and incident response. The scope of impact is limited to organizations using vulnerable versions of IBM QRadar SIEM.

## Recommendation

Prioritize patching of the affected IBM QRadar SIEM instances as specified by the vendor's security bulletin. Monitor access logs for unusual patterns of data retrieval or high volumes of unexpected queries originating from authenticated user accounts.
