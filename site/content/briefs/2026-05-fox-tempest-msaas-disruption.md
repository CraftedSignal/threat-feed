---
title: Fox Tempest Malware-Signing-as-a-Service Disrupted by Microsoft
slug: 2026-05-fox-tempest-msaas-disruption
description: Microsoft disrupted Fox Tempest, a threat actor running a malware-signing-as-a-service (MSaaS) that abuses Microsoft Artifact Signing to generate short-lived code-signing certificates used to sign malware disguised as legitimate software, delivering ransomware and various information stealers to victims across multiple sectors.
date: "2026-05-19T16:07:44Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Fox Tempest
tags:
  - malware-signing
  - azure
  - defense-evasion
  - ransomware
vendors:
  - Microsoft
products:
  - Microsoft Artifact Signing
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://www.securityweek.com/microsoft-disrupts-malware-signing-service-run-by-fox-tempest/
rules:
  - title: Detect Suspicious Process Execution with Invalid Certificate
    description: Detects process execution of binaries with invalid or untrusted code signing certificates, potentially indicating malware signed using fraudulent services.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Azure Resource Creation from Unfamiliar Geolocation
    description: Detects unusual creation of Azure resources (tenants, subscriptions) from locations not typically associated with legitimate activity. Requires Azure activity logs.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1583
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

Microsoft disrupted a cybercrime service named Fox Tempest, which has been operating a malware-signing-as-a-service (MSaaS) since at least September 2025. This service abuses Microsoft Artifact Signing to generate short-lived code-signing certificates, which are then used to sign malware, disguising it as legitimate software and helping it evade detection. Fox Tempest has created over a thousand certificates and established hundreds of Azure tenants and subscriptions to support its operations. Microsoft has revoked over one thousand code-signing certificates attributed to Fox Tempest. The MSaaS has been used by several ransomware groups, including Vanilla Tempest (targeted in October 2025), and has delivered ransomware families such as Rhysida, Inc, Qilin, and Akira, as well as malware families like Lumma Stealer, Oyster, and Vidar.

## Attack Chain

1. Fox Tempest establishes fraudulent Azure tenants and subscriptions to support its operations.
2. The actor abuses Microsoft Artifact Signing to generate short-lived code-signing certificates.
3. Cybercriminals purchase the malware-signing-as-a-service.
4. Malware is signed with the fraudulently obtained certificates.
5. Signed malware is disguised as legitimate software.
6. Victims are tricked into downloading and executing the signed malware.
7. Malware executes, potentially leading to ransomware deployment or information theft.
8. Stolen data is exfiltrated, or systems are encrypted and held for ransom.

## Impact

The downstream impact of Fox Tempest's operations has resulted in attacks against a broad range of industry sectors, including healthcare, education, government, and financial services, impacting organizations globally including, but not limited to, the United States, France, India, and China. The service costs thousands of dollars, and Microsoft believes the threat actor made millions. Successful attacks lead to data theft, system compromise, and financial losses.

## Recommendation

*   Monitor for unusual Azure tenant and subscription creation activity, which may indicate attempts to establish infrastructure for similar MSaaS operations.
*   Enable and review logs for Microsoft Artifact Signing and code-signing certificate generation events to identify potential abuse.
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious process execution and file creation activity associated with malware signed by certificates potentially linked to Fox Tempest.
*   Block execution of known malware hashes (if available from other sources) to prevent initial compromise.
