---
title: Detection of Mimikatz Crypto Module Certificate and Key Export
slug: 2026-10-mimikatz-crypto-export
description: This detection identifies the creation of specific file extensions indicative of the Mimikatz 'crypto' module, which is used to export cryptographic keys and certificates during credential theft activities.
date: "2026-10-12T18:09:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - mimikatz
  - certificate-theft
  - endpoint-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
    evidence: The following analytic detects the creation of files with extensions commonly associated with the Mimikatz Crypto module.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This behavior is significant as it may indicate the use of Mimikatz to export cryptographic keys, which is a common tactic for credential theft.
    confidence_band: high
references:
  - https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_crypto.c#L628-L645
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1552.004/T1552.004.yaml#L377
rules:
  - title: Detect Mimikatz Crypto Module Exported Files
    description: Detects the creation of files with extensions commonly associated with Mimikatz crypto module certificate and key export activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1649
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for Mimikatz-related file extensions.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific file extensions used by Mimikatz crypto module.
  hunt_leads:
    - lead: Search for historical file creation events matching the monitored extensions to identify past compromise.
      technique_id: T1649
      data_needed:
        - Sysmon Event ID 11
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic uses endpoint filesystem data to identify specific file names.
---

The Mimikatz 'crypto' module is a specialized component used by threat actors to interact with the Windows CryptoAPI for the purpose of exporting certificates and associated private keys. This activity is a classic indicator of credential harvesting or the theft of sensitive cryptographic material from a compromised host. By targeting specific file extensions - such as .pvk, .p8k, .pfx, and .der - defenders can identify the use of Mimikatz or automated scripts (such as those found in Atomic Red Team) that perform these export operations. Detecting these files on disk shortly after creation is critical for identifying unauthorized attempts to exfiltrate identities and cryptographic assets, which can then be used for persistent access or further lateral movement within an environment.

## Attack Chain

1. Attacker gains local administrative or SYSTEM access to the target endpoint.
2. Attacker executes Mimikatz with elevated privileges to interact with the Windows Certificate Store.
3. Attacker loads the Mimikatz 'crypto' module to enumerate available certificates and private keys.
4. Attacker executes export commands for targeted certificates.
5. Mimikatz writes the exported keys and certificates to disk with specific extensions (e.g., .pvk, .pfx).
6. Attacker gathers these files for exfiltration or subsequent use in authentication bypass or impersonation.

## Impact

Successful exfiltration of cryptographic keys and certificates allows an attacker to impersonate identities, decrypt captured traffic, or bypass authentication mechanisms relying on certificate-based security. This can lead to broad unauthorized access within an organization's network, effectively bypassing standard password-based protections.

## Recommendation

- Deploy the provided Sigma rule to monitor for the creation of files with extensions associated with the Mimikatz crypto module.
- Prioritize alerts originating from high-value systems, such as domain controllers, file servers, or administrative workstations.
- Investigate the process associated with the file creation event to confirm if it is a legitimate administrative tool or a malicious binary.
- Consider removing .pfx files from the alert if they generate excessive noise, focusing initially on more specific extensions like .pvk and .p8k.
