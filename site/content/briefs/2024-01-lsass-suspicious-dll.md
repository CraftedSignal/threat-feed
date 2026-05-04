---
title: LSASS Loading Suspicious DLL
slug: 2024-01-lsass-suspicious-dll
description: Detection of LSASS loading an unsigned or untrusted DLL, which can indicate credential access attempts by malicious actors targeting sensitive information stored in the LSASS process.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lsass
  - dll-injection
  - windows
vendors:
  - Microsoft
  - McAfee
  - SecMaker AB
  - HID Global
  - Apple
  - Citrix Systems
  - Dell
  - Hewlett-Packard Company
  - Symantec Corporation
  - National Instruments Corporation
  - DigitalPersona
  - Novell
  - Gemalto
  - EasyAntiCheat Oy
  - Entrust Datacard Corporation
  - AuriStor
  - LogMeIn
  - VMware
  - Nubeva Technologies Ltd
  - Micro Focus
  - Yubico AB
  - Secure Endpoints
  - Sophos
  - Morphisec Information Security
  - Entrust
  - F5 Networks
  - Bit4id
  - Thales DIS CPL USA
  - Micro Focus International plc
  - HYPR Corp
  - Intel
  - PGP Corporation
  - Parallels International GmbH
  - FrontRange Solutions Deutschland GmbH
  - SecureLink
  - Tidexa OU
  - Amazon Web Services
  - SentryBay Limited
  - Audinate Pty Ltd
  - CyberArk Software
  - NVIDIA
  - Trend Micro
  - Fortinet
  - Carbon Black
products:
  - Windows
affected_os:
  - Windows
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
iocs:
  - type: hash_sha256
    value: 811a03a5d7c03802676d2613d741be690b3461022ea925eb6b2651a5be740a4c
  - type: hash_sha256
    value: 1181542d9cfd63fb00c76242567446513e6773ea37db6211545629ba2ecf26a1
  - type: hash_sha256
    value: ed6e735aa6233ed262f50f67585949712f1622751035db256811b4088c214ce3
  - type: hash_sha256
    value: 26be2e4383728eebe191c0ab19706188f0e9592add2e0bf86b37442083ae5e12
  - type: hash_sha256
    value: 9367e78b84ef30cf38ab27776605f2645e52e3f6e93369c674972b668a444faa
  - type: hash_sha256
    value: d46cc934765c5ecd53867070f540e8d6f7701e834831c51c2b0552aba871921b
  - type: hash_sha256
    value: 0f77a3826d7a5cd0533990be0269d951a88a5c277bc47cff94553330b715ec61
  - type: hash_sha256
    value: 4aca034d3d85a9e9127b5d7a10882c2ef4c3e0daa3329ae2ac1d0797398695fb
  - type: hash_sha256
    value: 86031e69914d9d33c34c2f4ac4ae523cef855254d411f88ac26684265c981d95
ioc_counts:
  hash_sha256: 9
rules:
  - title: LSASS Loading Untrusted DLL
    description: Detects LSASS loading a DLL that is not signed by a trusted vendor or has a known bad hash, indicating potential credential dumping activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - image_load
      - windows
  - title: LSASS Loading DLL with Expired Signature
    description: Detects LSASS loading a DLL with an expired signature, which may indicate a compromised or outdated component.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The Local Security Authority Subsystem Service (LSASS) is a critical Windows component that manages security policies and user authentication. Attackers often target LSASS to dump credentials, using techniques like injecting malicious DLLs. This detection focuses on identifying instances where LSASS loads a DLL that is either unsigned or not signed by a trusted vendor. The rule excludes known legitimate signatures and file hashes to reduce false positives. This activity is a strong indicator of credential access attempts, potentially leading to further compromise of the system and network. The signatures identified in the rule contain well-known software vendors like Microsoft, McAfee and Citrix.

## Attack Chain

1.  An attacker gains initial access to the system through various means (e.g., phishing, exploiting a vulnerability).
2.  The attacker elevates privileges to gain sufficient access to interact with the LSASS process.
3.  The attacker drops a malicious DLL onto the system, often disguised as a legitimate file.
4.  The attacker injects the malicious DLL into the LSASS process using techniques like Reflective DLL Injection.
5.  LSASS loads the injected DLL, granting the attacker access to sensitive credentials stored in memory.
6.  The malicious DLL dumps credentials, such as plaintext passwords or NTLM hashes.
7.  The attacker uses the stolen credentials for lateral movement to other systems on the network.
8.  The attacker achieves their final objective, such as data exfiltration or deploying ransomware.

## Impact

Successful exploitation leads to credential compromise, allowing attackers to move laterally within the network, access sensitive data, and potentially achieve complete domain dominance. This can result in data breaches, financial losses, and reputational damage. The impact depends on the level of access associated with the compromised credentials.

## Recommendation

*   Deploy the `LSASS Loading Untrusted DLL` Sigma rule to your SIEM to detect suspicious DLLs loaded by LSASS.
*   Investigate any alerts generated by the Sigma rule and review the loaded DLL's code signature and hash.
*   Block the identified SHA256 hashes listed in the IOC table to prevent the execution of known malicious DLLs.
*   Implement application whitelisting to restrict which DLLs can be loaded into LSASS.
*   Enable Sysmon process creation and image load logging to provide the necessary data for detection.
