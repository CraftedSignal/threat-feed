---
title: Pass-ta-key Attacks Targeting Google Chrome Passkey Implementation
slug: 2026-08-pass-ta-key-attacks
description: Researchers identified multiple techniques allowing malware on Windows hosts to hijack Google-synced passkeys by extracting cryptographic material and forging authentication assertions.
date: "2026-08-05T13:18:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - passkey
  - credential-access
  - browser-security
  - identity
vendors:
  - Google
products:
  - Chrome
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The malware can examine the browser’s local synchronization database to identify which online accounts the user has protected with passkeys, along with associated usernames and encrypted credential material.
    confidence_band: high
references:
  - https://www.securityweek.com/new-attack-methods-enable-malware-to-hijack-passkey-protected-accounts/
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Review endpoint security policies to ensure browser data directories are protected from unauthorized access.
      owner: SOC
      due: 72h
      evidence: Threat focuses on local synchronization database access.
  hunt_leads:
    - lead: Identify non-browser processes attempting to read Chrome synchronization files.
      technique_id: T1555.003
      data_needed:
        - File system access monitoring
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers access browser synchronization databases.
---

Palo Alto Networks researchers have disclosed a series of attack methods, collectively termed 'Pass-ta-key', that target the implementation of Google-synced passkeys on the Google Chrome browser for Windows. These techniques allow malware already running on a compromised host to hijack passkey-protected accounts without requiring user interaction, biometric prompts, or privilege escalation. The attacks exploit the manner in which Chrome manages local synchronization databases and device identity keys. By accessing these local assets or extracting secrets directly from browser process memory, attackers can generate valid authentication assertions that the Google cloud authenticator service accepts as legitimate. The severity ranges from simple credential use to the 'Golden Pass-ta-key' variant, which facilitates the decryption of synchronized passkey material, potentially leading to long-term account compromise. These findings highlight a critical risk to passwordless authentication flows when the underlying browser environment is compromised.

## Attack Chain

1. The attacker gains initial access to a Windows host and executes malware with the permissions of the current user.
2. The malware identifies the presence of a Google Chrome browser instance and locates the local synchronization database on disk.
3. The malware reads the browser database to identify protected accounts and associated usernames.
4. The malware accesses Windows cryptographic APIs or directly parses browser process memory to retrieve the device identity key or master secret.
5. The malware receives an authentication challenge from the Google cloud authenticator service.
6. The malware uses the extracted cryptographic material to sign the challenge, simulating a legitimate device response.
7. The malware forwards the signed authentication assertion to the target website, successfully completing the login process.
8. In advanced variants, the malware registers its own verification key or decrypts the stored master secret to maintain persistent access or decrypt future credentials.

## Impact

The vulnerability affects the security of Google-synced passkeys on Windows devices. Successful exploitation enables unauthorized account access, bypassing intended phishing-resistant MFA protections. Because these attacks occur entirely on the client side without user notification or interaction, they are highly stealthy. Widespread adoption of passkeys makes the potential for large-scale account hijacking significant if these methods are weaponized by threat actors.

## Recommendation

Prioritize the implementation of robust endpoint detection and response (EDR) solutions to identify unauthorized process memory access and suspicious local file reads targeting browser-specific data directories. Monitor for unusual interactions with Windows cryptographic APIs, particularly when initiated by non-browser or unknown processes. Given that these attacks rely on pre-existing malware on the host, focus defensive efforts on preventing initial access and restricting the ability of malicious binaries to access browser data files.
