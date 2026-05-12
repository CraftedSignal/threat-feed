---
title: Wing FTP Server 8.1.2 Authenticated Remote Code Execution via Session Serialization (CVE-2026-44403)
slug: 2026-05-wing-ftp-rce
description: Wing FTP Server 8.1.2 contains an authenticated remote code execution vulnerability (CVE-2026-44403) in the session serialization mechanism, allowing administrators to inject arbitrary Lua code and achieve remote code execution.
date: "2026-05-12T21:16:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - rce
  - code-injection
vendors:
  - Wing
products:
  - Wing FTP Server 8.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-44403
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44403
  - https://www.vulncheck.com/advisories/wing-ftp-server-authenticated-remote-code-execution-via-session-serialization
rules:
  - title: Detect Wing FTP Server CVE-2026-44403 RCE Attempt
    description: Detects CVE-2026-44403 exploitation attempt — attempts to inject malicious Lua code into the domain admin mydirectory field.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - webserver
  - title: Detect Wing FTP Server Suspicious Lua Load
    description: Detects suspicious Lua loading activity potentially related to CVE-2026-44403 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Wing FTP Server 8.1.2 is vulnerable to authenticated remote code execution (CVE-2026-44403) due to unsafe session serialization. An authenticated administrator can inject arbitrary Lua code through the `mydirectory` field within the domain admin settings. This vulnerability stems from the server's failure to properly escape closing delimiters when serializing session values into Lua source code. Successful exploitation allows attackers to execute arbitrary code on the server when the poisoned session is loaded using the `loadfile()` function. This is a high-severity vulnerability as it allows for complete compromise of the affected server.

## Attack Chain

1.  The attacker authenticates to the Wing FTP Server as an administrator.
2.  The attacker navigates to the domain admin settings.
3.  The attacker modifies the `mydirectory` field with a malicious Lua payload containing code injection.
4.  The server serializes the session data, including the injected Lua code, into a session file without proper sanitization.
5.  The server saves the modified session data.
6.  The server loads the session file, using the `loadfile()` function to interpret the session data as Lua code.
7.  The injected Lua code is executed due to the insecure deserialization process.
8.  The attacker achieves remote code execution on the server.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44403) grants the attacker the ability to execute arbitrary code on the Wing FTP Server. This can lead to complete compromise of the server, including data theft, modification, or destruction. Given that FTP servers are often used to store sensitive data, this vulnerability poses a significant risk to data confidentiality and integrity. There is no information about the number of victims, but any organization using Wing FTP Server 8.1.2 with admin accounts exposed is at risk.

## Recommendation

*   Upgrade to a patched version of Wing FTP Server that addresses CVE-2026-44403.
*   Deploy the Sigma rule `Detect Wing FTP Server CVE-2026-44403 RCE Attempt` to detect attempts to exploit this vulnerability.
*   Monitor Wing FTP Server logs for suspicious activity related to session management and Lua code execution using the `Detect Wing FTP Server Suspicious Lua Load` rule.
