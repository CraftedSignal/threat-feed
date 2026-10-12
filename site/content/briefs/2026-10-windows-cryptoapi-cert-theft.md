---
title: Detection of Authentication Certificate Extraction via Windows CryptoAPI
slug: 2026-10-windows-cryptoapi-cert-theft
description: This detection identifies the illicit extraction of authentication certificates by monitoring Windows CAPI2 logs for EventID 70, a technique commonly utilized by attackers to perform credential theft and user impersonation.
date: "2026-10-12T18:22:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - cpi2
  - certificate-theft
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: The following analytic detects the extraction of authentication certificates using Windows Event Log - CAPI2 (CryptoAPI 2).
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749296(v=ws.10)
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1649/T1649.yaml
rules:
  - title: Detect Authentication Certificate Private Key Acquisition
    description: Detects the acquisition of a certificate's private key via Windows CAPI2 EventID 70, which may indicate unauthorized certificate extraction.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1649
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Microsoft-Windows-CAPI2/Operational logging on critical endpoints
      owner: IT Operations
      due: 72h
      evidence: Source states log is necessary to capture EventID 70
  hunt_leads:
    - lead: Search for EventID 70 in CAPI2 logs for signs of mass certificate access
      technique_id: T1649
      data_needed:
        - CAPI2/Operational log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is significant because it can identify potential misuse of certificates
---

The extraction of authentication certificates from the Windows certificate store is a critical phase in credential access attacks. This activity is frequently observed when adversaries utilize specialized tools, such as Mimikatz or Cobalt Strike, to acquire private keys associated with certificates. By monitoring the Microsoft-Windows-CAPI2/Operational log, specifically EventID 70, security teams can identify when a private key is accessed or exported. This technique is often linked to sophisticated actors, including those involved in ransomware operations like Hellcat, who leverage compromised certificates to impersonate legitimate users, escalate privileges, or maintain persistence within a network. Given that CAPI2 logging is not enabled by default and serves as a debug-level log, detection engineers must ensure proper log enablement and tuning to mitigate the risk of excessive noise from legitimate administrative operations.

## Impact

Successful exploitation of this technique enables attackers to bypass standard authentication mechanisms by impersonating high-privilege users or service accounts. This facilitates lateral movement, unauthorized access to sensitive data, and further privilege escalation, ultimately posing a severe threat to the integrity and confidentiality of the organization's identity infrastructure.

## Recommendation

* Enable the Microsoft-Windows-CAPI2/Operational log on all Windows endpoints to capture EventID 70.
* Deploy the provided Sigma rule to monitor for certificate private key acquisition events.
* Tune the detection logic by filtering known administrative tools or legitimate system services that perform authorized certificate maintenance to reduce false positives.
* Review the documentation provided by Red Canary's Atomic Red Team (T1649) to validate your organization's logging posture against this specific TTP.
