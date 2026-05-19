---
title: Fox Tempest Malware-Signing-as-a-Service Operation
slug: 2026-05-fox-tempest-msaas
description: Fox Tempest is a financially motivated threat actor operating a malware-signing-as-a-service (MSaaS) used by other cybercriminals to distribute malicious code, including ransomware, by abusing Microsoft Artifact Signing to generate fraudulent code-signing certificates and evade security controls.
date: "2026-05-19T16:01:22Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Fox Tempest
tags:
  - malware-signing
  - ransomware
  - supply-chain
vendors:
  - Microsoft
products:
  - Artifact Signing
  - Microsoft Defender
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/19/exposing-fox-tempest-a-malware-signing-service-operation/
iocs:
  - type: domain
    value: signspace[.]cloud
ioc_counts:
  domain: 1
rules:
  - title: Detect Signed Executables from Suspicious Paths
    description: Detects execution of signed executables from suspicious or unusual file paths, potentially indicating malware masquerading as legitimate software.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1036.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Azure Artifact Signing Abuse
    description: Detects suspicious activity related to Azure Artifact Signing, potentially indicating abuse by threat actors to sign malicious code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1588.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Fox Tempest is a financially motivated threat actor operating a malware-signing-as-a-service (MSaaS) since at least May 2025. They provide fraudulent code-signing certificates to other cybercriminals, enabling them to distribute malicious code, including ransomware, more effectively. Fox Tempest abuses Microsoft Artifact Signing to generate short-lived, fraudulent code-signing certificates to appear legitimately signed, which allows malware to evade security controls. Microsoft has tracked Fox Tempest since September 2025 and disrupted their MSaaS offering in May 2026. The group has created over a thousand certificates and established hundreds of Azure tenants and subscriptions to support its operations. The group's activities enable the deployment of ransomware, such as Rhysida, and distribution of malware families like Lumma Stealer.

## Attack Chain

1. Fox Tempest establishes infrastructure on Azure, creating hundreds of tenants and subscriptions.
2. They fraudulently obtain short-lived (72-hour) code-signing certificates through Microsoft Artifact Signing by likely using stolen identities to pass the identity validation process.
3. Fox Tempest operates the SignSpace[.]cloud service, offering it to other cybercriminals.
4. Customers (other threat actors) upload malicious files to the SignSpace service to be signed using Fox Tempest-controlled certificates.
5. The SignSpace service uses the fraudulently obtained certificates to sign the uploaded malware.
6. Threat actors distribute the signed malware through various methods, including legitimate purchased advertisements, malvertising, and SEO poisoning, leveraging the trusted signature to bypass security controls.
7. Users download and execute the signed malware, believing it to be legitimate software such as AnyDesk, Teams, Putty, or Webex.
8. The executed malware leads to further compromise, potentially including ransomware deployment, credential theft, and data exfiltration.

## Impact

Fox Tempest's MSaaS enables the distribution of malware, including ransomware, across a broad range of industry sectors, including healthcare, education, government, and financial services. Organizations globally, including those in the United States, France, India, and China, have been impacted. Cryptocurrency analysis has linked Fox Tempest to ransomware affiliates responsible for delivering several prominent ransomware families, including INC, Qilin, and Akira, with observed proceeds in the millions. Successful attacks can lead to data breaches, financial losses, and disruption of services.

## Recommendation

*   Monitor network traffic for connections to known malware distribution domains and IPs used in campaigns leveraging fraudulently signed binaries.
*   Implement application control policies to only allow execution of signed binaries from trusted vendors. Prioritize blocking certificates revoked by Microsoft (see Overview).
*   Monitor process creation events for execution of signed binaries from untrusted or unexpected locations (see rule: "Detect Signed Executables from Suspicious Paths").
*   Deploy the Sigma rule "Detect Azure Artifact Signing Abuse" to identify potential abuse of Azure Artifact Signing within your environment.
