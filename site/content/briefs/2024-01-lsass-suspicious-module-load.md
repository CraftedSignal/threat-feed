---
title: Suspicious Module Loaded by LSASS for Credential Access
slug: 2024-01-lsass-suspicious-module-load
description: Detection of unsigned or untrusted DLLs being loaded into the LSASS process, which is indicative of credential access attempts by adversaries aiming to steal sensitive information such as user passwords.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lsass
  - windows
vendors:
  - Elastic
  - Algorithmic Research LTD.
  - Amazon Web Services, Inc.
  - Apple Inc.
  - Audinate Pty Ltd
  - AuriStor, Inc.
  - Bit4id
  - Carbon Black, Inc.
  - Check Point Software Technologies Ltd.
  - Citrix Systems, Inc.
  - CyberArk Software Ltd.
  - Dell Inc
  - DigitalPersona, Inc.
  - EasyAntiCheat Oy
  - Entrust Corporation
  - Entrust Datacard Corporation
  - Entrust, Inc.
  - F5 Networks Inc
  - Fortinet
  - FrontRange Solutions Deutschland GmbH
  - GEMALTO SA
  - Hewlett-Packard Company
  - HID Global
  - HYPR Corp
  - IDEMIA IDENTITY & SECURITY FRANCE SAS
  - Intel
  - Istituto Poligrafico e Zecca dello Stato S.p.A.
  - LogMeIn, Inc.
  - McAfee
  - Micro Focus
  - Microsoft
  - Morphisec Information Security 2014 Ltd
  - Musarubra US LLC
  - National Instruments Corporation
  - Novell, Inc.
  - Nubeva Technologies Ltd
  - NVIDIA
  - Palo Alto Networks
  - Parallels International GmbH
  - PGP Corporation
  - QUEST SOFTWARE INC.
  - SecMaker AB
  - Secure Endpoints, Inc.
  - SecureLink, Inc.
  - SentinelOne Inc.
  - SentryBay Limited
  - Sophos Ltd
  - Symantec Corporation
  - Thales DIS CPL USA, Inc.
  - Tidexa OU
  - Trend Micro
  - VMware
  - Yubico AB
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://blog.xpnsec.com/exploring-mimikatz-part-2/
  - https://github.com/jas502n/mimikat_ssp
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_lsass_loaded_susp_dll.toml
rules:
  - title: LSASS Loading Unsigned or Untrusted DLL
    description: Detects LSASS loading a DLL that is either unsigned or not signed by a trusted vendor, which may indicate credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: LSASS Loading DLL with Suspicious Hash
    description: Detects LSASS loading a DLL with a known malicious SHA256 hash, which could indicate credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This rule detects the loading of unsigned or untrusted DLLs into the Local Security Authority Subsystem Service (LSASS) process on Windows systems. LSASS is a critical component responsible for managing security policies and handling user authentication, making it a prime target for credential theft. Attackers often attempt to load malicious DLLs into LSASS to gain access to encrypted and plaintext passwords. This can lead to the compromise of user accounts, including domain administrator accounts. The Elastic detection rule identifies such threats by monitoring for DLLs loaded into the LSASS process that do not have valid code signatures from trusted vendors, or that do not match a list of known good DLL hashes or file paths. The rule was last updated in May 2026, but the underlying threat remains relevant for modern environments.

## Attack Chain

1.  The attacker gains initial access to the system through various means (e.g., phishing, exploiting vulnerabilities).
2.  The attacker obtains local administrator privileges on the target system.
3.  The attacker drops a malicious DLL onto the file system.
4.  The attacker configures the system to load the malicious DLL into the LSASS process. This can be achieved by modifying registry keys related to Security Support Providers (SSPs).
5.  LSASS loads the malicious DLL during system startup or a subsequent event that triggers SSP loading.
6.  The malicious DLL intercepts and captures credentials handled by LSASS, such as user passwords and smart card PINs.
7.  The attacker retrieves the captured credentials.
8.  The attacker uses the stolen credentials to escalate privileges or move laterally within the network.

## Impact

A successful attack can lead to the compromise of user accounts, including those with domain administrator privileges. This allows the attacker to gain complete control over the affected Windows domain, potentially leading to data breaches, ransomware deployment, or other malicious activities. The impact is significant, as LSASS is a core component of the Windows security model. The number of potential victims depends on the scope of the attacker's lateral movement and the privileges they gain.

## Recommendation

*   Deploy the Sigma rule "LSASS Loading Unsigned or Untrusted DLL" to your SIEM to detect suspicious DLLs being loaded into LSASS.
*   Enable Sysmon event logging for process creation and module loading events to provide the necessary data for the Sigma rule to function.
*   Regularly review and update the exclusion lists in the Sigma rule to account for legitimate software vendors and DLLs specific to your environment.
*   Implement application whitelisting to prevent unauthorized DLLs from being loaded into critical processes like LSASS.
*   Monitor registry modifications related to Security Support Providers (SSPs) to detect unauthorized changes that could lead to malicious DLL loading.
*   Investigate any alerts generated by the Sigma rule promptly, following the triage and analysis steps outlined in the rule's documentation.
