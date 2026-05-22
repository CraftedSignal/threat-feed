---
title: Rare Connection to WebDAV Target via Rundll32
slug: 2026-05-rare-webdav-destination
description: This rule identifies rare connection attempts to a Web Distributed Authoring and Versioning (WebDAV) resource, where attackers may inject WebDAV paths in files or features opened by a victim user to leak their NTLM credentials via forced authentication using rundll32.exe.
date: "2026-05-22T18:36:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - defense-evasion
  - windows
vendors:
  - Elastic
  - Microsoft
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1187/
rules:
  - title: Detect Rare WebDAV Destination via Rundll32
    description: Detects a rare connection attempt to a WebDAV resource using rundll32.exe, which could indicate forced authentication and NTLM credential leakage (T1187, T1218.011).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1187
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect WebDAV Connection via Process CommandLine
    description: Detects a rare connection attempt to a WebDAV resource via command line, which could indicate forced authentication and NTLM credential leakage (T1187, T1218.011).
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1187
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies rare connection attempts to a Web Distributed Authoring and Versioning (WebDAV) resource. Attackers can inject WebDAV paths in files or features opened by a victim user to force authentication and leak their NTLM credentials. The rule focuses on the execution of `rundll32.exe` with command-line arguments indicative of WebDAV exploitation, specifically the use of `DavSetCookie`. The rule is designed to detect unusual WebDAV server destinations by excluding common legitimate services and private IP ranges. The rule is intended to detect credential access attempts facilitated by forced authentication.

## Attack Chain

1.  The attacker crafts a malicious document or link containing a WebDAV path.
2.  The victim user opens the malicious document or clicks the link.
3.  The operating system attempts to access the specified WebDAV resource using `rundll32.exe` with the `DavSetCookie` parameter.
4.  The `rundll32.exe` process initiates a connection to the attacker-controlled WebDAV server.
5.  The victim's system sends NTLM credentials to the attacker's WebDAV server.
6.  The attacker captures the NTLM credentials.
7.  The attacker relays the captured NTLM credentials to authenticate to other systems.

## Impact

Successful exploitation leads to the leakage of the victim's NTLM credentials. This allows the attacker to potentially gain unauthorized access to other systems and resources within the network where the victim's credentials are valid. The impact is credential access and lateral movement.

## Recommendation

*   Deploy the Sigma rule `Detect Rare WebDAV Destination via Rundll32` to your SIEM and tune for your environment.
*   Enable process creation logging with command line monitoring to detect the execution of `rundll32.exe` with WebDAV-related parameters.
*   Monitor network connections for unusual outbound traffic to WebDAV servers.
*   Educate users about the risks of opening suspicious documents or clicking on untrusted links to prevent initial access.
