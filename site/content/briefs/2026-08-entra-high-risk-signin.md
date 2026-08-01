---
title: Monitoring High-Risk Sign-ins in Microsoft Entra ID
slug: 2026-08-entra-high-risk-signin
description: This brief details the detection of compromised cloud accounts by leveraging Microsoft Identity Protection telemetry to identify high-risk authentication events indicative of credential abuse.
date: "2026-08-01T01:42:00Z"
lastmod: "2026-08-01T01:45:33Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cloud
  - identity
  - account-compromise
vendors:
  - Microsoft
  - Google
products:
  - Microsoft Entra ID
  - Microsoft 365
  - Windows
  - Android
affected_os:
  - Windows
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This rule detects high-risk sign-ins in Microsoft Entra ID as identified by Identity Protection.
    confidence_band: high
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection
  - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
rules:
  - title: Detect High Risk Microsoft Entra ID Sign-in
    description: Detects high-risk sign-ins in Microsoft Entra ID as identified by Identity Protection machine learning and heuristics.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-01T01:45:33Z"
    level: L1
    summary: OS windows; OS android
    sources:
      - microsoft-threat-intel
    source_urls:
      - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
---

Microsoft Entra ID utilizes machine learning and heuristic analysis through Microsoft Identity Protection to evaluate the risk associated with every authentication request. When a sign-in event is flagged with a 'high' risk level, it indicates a strong likelihood of credential compromise or unauthorized access. This detection mechanism is critical for Security Operations centers as it enables the identification of accounts under active attack, even when the threat actor is using valid credentials. Defenders should focus on these high-risk events to catch account takeovers in progress before the attacker can perform lateral movement or data exfiltration within the cloud environment.

## Impact

Successful compromise of cloud accounts through valid credentials can lead to unauthorized access to sensitive corporate data, lateral movement within the cloud ecosystem, and persistent access to enterprise applications. High-risk sign-ins serve as a primary indicator that an account's security posture has been degraded, potentially affecting any sector relying on Microsoft Entra ID for identity and access management.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to trigger alerts on high-risk sign-in logs originating from Microsoft Entra ID.
- Integrate Microsoft Entra ID sign-in logs into your security analytics platform to correlate risk scores with geolocation and device telemetry.
- Review and enforce Conditional Access policies that automatically block or require MFA for sign-ins designated as 'high' risk by Microsoft Identity Protection.
- Establish a standardized triage workflow for 'high' risk sign-ins, including account suspension and token revocation for confirmed unauthorized access.
