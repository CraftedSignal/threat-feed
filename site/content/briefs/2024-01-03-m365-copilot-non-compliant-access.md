---
title: M365 Copilot Access from Non-Compliant Devices
slug: 2024-01-03-m365-copilot-non-compliant-access
description: Detects Microsoft 365 (M365) Copilot access from non-compliant or unmanaged devices, potentially indicating shadow IT, BYOD policy violations, or compromised endpoints accessing sensitive data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - m365
  - copilot
  - device-compliance
  - byod
  - shadow-it
vendors:
  - Microsoft
products:
  - M365 Copilot
  - Azure AD
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.splunk.com/en_us/blog/artificial_intelligence/m365-copilot-log-analysis-splunk.html
rules:
  - title: M365 Copilot Access from Non-Compliant Devices
    description: Detects M365 Copilot access from devices that are not marked as compliant or managed.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
      - windows
  - title: M365 Copilot Access from Non-Compliant Devices - Anomaly Detection
    description: Detects anomalous access patterns to M365 Copilot from non-compliant devices based on user, OS, and browser combinations.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - webserver
      - windows
rules_count: 2
---

This detection identifies instances where users access M365 Copilot from devices that do not meet corporate compliance standards. This can expose sensitive organizational data. The activity is identified by analyzing M365 Copilot Graph API logs for access events originating from devices flagged as either non-compliant (deviceDetail.isCompliant=false) or unmanaged (deviceDetail.isManaged=false). The detection aggregates information by user, operating system, and browser to provide context around the non-compliant access. The goal is to uncover potential shadow IT usage, violations of Bring Your Own Device (BYOD) policies, or compromised endpoints accessing corporate resources through M365 Copilot. This detection is based on version 4 of the Splunk ESCU detection `e26bc52d-9cbc-4743-9745-e8781d935042`.

## Attack Chain

1. User attempts to access Microsoft 365 Copilot application.
2. Azure AD evaluates device compliance and management status during authentication.
3. If the device is not compliant (deviceDetail.isCompliant=false) or unmanaged (deviceDetail.isManaged=false), the sign-in attempt is logged in Azure AD Sign-in logs.
4. The M365 Copilot Graph API captures the sign-in event and its associated device details.
5. Security monitoring tools ingest the M365 Copilot Graph API logs.
6. The detection identifies events where `deviceDetail.isCompliant` or `deviceDetail.isManaged` is false while accessing Copilot.
7. The detection aggregates the data by user, device operating system, and browser to highlight patterns of non-compliant access.
8. Security teams are alerted to the potential policy violations or compromised endpoints accessing M365 Copilot.

## Impact

Successful exploitation can lead to data leakage, unauthorized access to sensitive information, and violation of corporate security policies. The number of affected users and the sensitivity of data accessed depend on the organization's M365 Copilot usage and the data accessible through Copilot. Organizations may face compliance violations and regulatory fines if sensitive data is accessed from non-compliant devices. This situation impacts the security domain of endpoints, which can introduce threats into web applications and expose company data.

## Recommendation

*   Ensure the Splunk Add-on for Microsoft Office 365 is properly configured to ingest Azure AD Sign-in logs via the Graph API, as described in the "how_to_implement" section.
*   Deploy the Sigma rule `M365 Copilot Access from Non-Compliant Devices` to detect unauthorized access attempts and tune it for your environment.
*   Investigate users flagged by the detection, focusing on devices labeled as non-compliant or unmanaged in the M365 Copilot Graph API logs.
*   Develop or refine BYOD policies to address the risks of accessing corporate resources from personal devices and communicate these policies clearly to employees.
*   Implement stricter Conditional Access policies in Azure AD to block access to M365 Copilot from non-compliant or unmanaged devices, using device compliance as a condition.
*   Regularly review and update device compliance policies to ensure they align with current security best practices.
