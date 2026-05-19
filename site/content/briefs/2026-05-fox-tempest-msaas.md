---
title: Fox Tempest Malware-Signing-as-a-Service Disrupted
slug: 2026-05-fox-tempest-msaas
description: Microsoft disrupted a malware-signing-as-a-service (MSaaS) operation run by Fox Tempest that abused the Azure Artifact Signing service to generate fraudulent code-signing certificates, enabling malware to bypass security controls.
date: "2026-05-19T21:48:34Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Fox Tempest
tags:
  - code-signing
  - malware-signing
  - supply-chain
  - azure
vendors:
  - Microsoft
  - Cloudzy
  - AnyDesk
  - Webex
products:
  - Azure Artifact Signing
  - Microsoft Teams
  - AnyDesk
  - PuTTY
  - Webex
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/
iocs:
  - type: domain
    value: signspace[.]cloud
ioc_counts:
  domain: 1
rules:
  - title: Detect Signed Executables Impersonating Legitimate Software
    description: Detects the execution of signed executables impersonating legitimate software like Microsoft Teams, AnyDesk, PuTTY, and Webex, potentially indicating malware signed by the Fox Tempest MSaaS.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1588.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Uncommon Process Execution from Downloads Folder
    description: Detects executables running from the Downloads folder which are signed, but lack a valid digital signature.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

In May 2026, Microsoft disrupted a malware-signing-as-a-service (MSaaS) operation run by the threat actor Fox Tempest. This operation abused the Azure Artifact Signing service (formerly Trusted Signing) to generate fraudulent code-signing certificates. These certificates were then used by cybercriminals, including ransomware gangs, to sign malware, making it appear legitimate to users and operating systems. Fox Tempest created over 1,000 certificates and hundreds of Azure tenants and subscriptions to support its operation. The service was linked to numerous malware and ransomware campaigns, including Oyster, Lumma Stealer, Vidar, Rhysida, Akira, INC, and BlackByte. The MSaaS platform was promoted on a Telegram channel named "EV Certs for Sale by SamCodeSign," with prices ranging from $5,000 to $9,000 in Bitcoin.

## Attack Chain

1. Fox Tempest creates hundreds of Azure tenants and subscriptions.
2. The threat actor abuses the Azure Artifact Signing service to generate short-lived (72-hour) code-signing certificates.
3. Cybercriminal customers upload malicious files to the MSaaS platform through signspace[.]cloud or pre-configured virtual machines hosted on Cloudzy infrastructure.
4. Fox Tempest signs the uploaded malware using the fraudulently obtained certificates.
5. Attackers distribute signed malware, impersonating legitimate software such as Microsoft Teams, AnyDesk, PuTTY, and Webex.
6. Unsuspecting victims execute the falsely named installer files.
7. The installers deliver a malicious loader, which installs the fraudulently signed malware, such as Oyster.
8. The malware deploys ransomware, such as Rhysida, or steals credentials and sensitive information using Lumma Stealer or Vidar.

## Impact

The Fox Tempest MSaaS operation enabled cybercriminals to sign their malware with certificates trusted by the Windows operating system, allowing them to bypass security controls and infect systems more easily. This led to successful ransomware attacks and data theft, causing significant financial losses and reputational damage for victim organizations. Microsoft believes the operation generated millions of dollars in profits.

## Recommendation

*   Block the domain `signspace[.]cloud` at the DNS resolver to prevent access to the MSaaS platform.
*   Deploy the Sigma rules below to your SIEM to detect the execution of signed malware installers that impersonate legitimate software.
*   Monitor for suspicious Azure tenant and subscription creation activities that may indicate abuse of the Artifact Signing service.
