---
title: WWBN AVideo Unauthenticated Remote Code Execution via CloneSite Plugin
slug: 2024-01-10-avideo-rce
description: Unauthenticated attackers can achieve remote code execution in WWBN AVideo versions up to 26.0 by chaining vulnerabilities in the CloneSite plugin related to exposed secrets, database dumps, and OS command injection.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - command-injection
  - credential-access
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33478
rules:
  - title: AVideo CloneSite Plugin Unauthorized Secret Key Exposure
    description: Detects unauthorized requests to the clones.json.php endpoint, which exposes clone secret keys.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: AVideo CloneSite Plugin Command Injection Attempt
    description: Detects suspicious requests to cloneClient.json.php that may indicate command injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to remote code execution (RCE) in versions up to and including 26.0. The vulnerability resides within the CloneSite plugin and can be exploited by unauthenticated attackers. This exploit chain involves accessing sensitive clone secret keys without authentication, leading to a database dump containing weakly hashed (MD5) admin passwords. Successful cracking of these passwords allows the attacker to leverage an OS command injection flaw within the `cloneClient.json.php` script, specifically within the rsync command construction. This command injection leads to arbitrary system command execution, granting full control of the affected AVideo server. The vulnerability was patched in commit c85d076375fab095a14170df7ddb27058134d38c.

## Attack Chain

1. An unauthenticated attacker sends a request to the `clones.json.php` endpoint.
2. The `clones.json.php` endpoint exposes clone secret keys without requiring authentication.
3. The attacker uses the exposed clone secret keys to trigger a full database dump via `cloneServer.json.php`.
4. The database dump contains admin password hashes stored as MD5.
5. The attacker cracks the MD5 hashed admin passwords due to their weak cryptographic algorithm.
6. With the cracked admin credentials, the attacker authenticates to the AVideo admin panel.
7. The attacker exploits an OS command injection vulnerability in the `cloneClient.json.php` script during rsync command construction.
8. The attacker executes arbitrary system commands on the AVideo server, achieving remote code execution.

## Impact

Successful exploitation of this vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the target system. This can lead to complete system compromise, data theft, modification, or destruction. The impact includes potential defacement of the video platform, unauthorized access to sensitive video content and user data, and the use of the compromised server for further malicious activities. Given the ease of exploitation and the critical nature of the vulnerability, affected organizations are at significant risk.

## Recommendation

*   Apply the patch from commit c85d076375fab095a14170df7ddb27058134d38c to remediate CVE-2026-33478.
*   Deploy the Sigma rules to detect exploitation attempts targeting the `clones.json.php` and `cloneClient.json.php` endpoints.
*   Monitor web server logs for requests to `clones.json.php` and `cloneServer.json.php` without prior authentication.
*   Implement strong password policies and hashing algorithms (e.g., bcrypt, Argon2) for admin passwords in AVideo to mitigate the impact of database dumps.
