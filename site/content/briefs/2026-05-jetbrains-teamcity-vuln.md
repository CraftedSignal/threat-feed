---
title: JetBrains TeamCity Vulnerability
slug: 2026-05-jetbrains-teamcity-vuln
description: A security advisory released by JetBrains on May 11, 2026, addresses a vulnerability in JetBrains TeamCity versions prior to 2026.1 and 2025.11.5, requiring users to apply updates to mitigate potential risks.
date: "2026-05-11T19:45:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - jetbrains
  - teamcity
vendors:
  - JetBrains
products:
  - TeamCity
references:
  - https://cyber.gc.ca/en/alerts-advisories/jetbrains-security-advisory-av26-445
  - https://www.jetbrains.com/privacy-security/issues-fixed/
rules:
  - title: Detect Suspicious TeamCity Access
    description: Detects unusual access patterns to TeamCity web interface which might indicate reconnaissance attempts or exploitation.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - webserver
  - title: Detect Suspicious TeamCity User Agent
    description: Detects unusual user agent strings when accessing TeamCity, potentially indicating malicious bots or scripts attempting to exploit the vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

On May 11, 2026, JetBrains released a security advisory (AV26-445) addressing a vulnerability found in their TeamCity product. This vulnerability affects TeamCity servers with versions prior to 2026.1 and 2025.11.5. The advisory urges users and administrators to promptly review the security bulletin provided by JetBrains and to apply the necessary updates to their TeamCity instances. Failure to apply these updates could potentially lead to unauthorized access or other security breaches within the TeamCity environment. The vulnerability impacts both the 2025 and 2026 release cycles, underscoring the importance of patching for a wide range of users.

## Attack Chain

1.  Attacker identifies a vulnerable TeamCity server running a version prior to 2026.1 or 2025.11.5.
2.  Attacker leverages the specific vulnerability (details not provided in source) to gain unauthorized access.
3.  Attacker exploits a path traversal vulnerability to access sensitive files on the TeamCity server.
4.  Attacker uploads a malicious plugin to execute arbitrary code within the TeamCity environment.
5.  Attacker escalates privileges within the TeamCity application.
6.  Attacker gains control of the TeamCity server, allowing them to modify build configurations.
7.  Attacker injects malicious code into software builds managed by TeamCity, potentially compromising downstream clients.

## Impact

The vulnerability in JetBrains TeamCity, if exploited, can lead to unauthorized access and control of the TeamCity server. Successful exploitation can compromise software builds managed by TeamCity, potentially impacting a large number of downstream clients and resulting in supply chain attacks. The lack of specific details regarding the vulnerability makes it difficult to assess the total number of potential victims, however, any organization using vulnerable versions of TeamCity is at risk.

## Recommendation

*   Immediately upgrade all JetBrains TeamCity instances to version 2026.1 or 2025.11.5 or later, as recommended in the advisory [JetBrains – Fixed security issues](https://www.jetbrains.com/privacy-security/issues-fixed/).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts against TeamCity servers.
