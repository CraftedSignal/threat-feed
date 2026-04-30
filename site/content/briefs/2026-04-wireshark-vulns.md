---
title: Multiple Vulnerabilities in Wireshark Lead to Remote Code Execution and Denial of Service
slug: 2026-04-wireshark-vulns
description: Multiple vulnerabilities in Wireshark versions 4.4.x before 4.4.15 and 4.6.x before 4.6.5 could allow remote attackers to execute arbitrary code, cause a denial of service, or compromise data confidentiality.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wireshark
  - vulnerability
  - rce
  - dos
vendors:
  - Wireshark
products:
  - Wireshark 4.4.x
  - Wireshark 4.6.x
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0518/
  - https://www.wireshark.org/security/wnpa-sec-2026-08.html
  - https://www.wireshark.org/security/wnpa-sec-2026-09.html
  - https://www.wireshark.org/security/wnpa-sec-2026-10.html
  - https://www.wireshark.org/security/wnpa-sec-2026-11.html
  - https://www.wireshark.org/security/wnpa-sec-2026-12.html
  - https://www.wireshark.org/security/wnpa-sec-2026-13.html
  - https://www.wireshark.org/security/wnpa-sec-2026-14.html
  - https://www.wireshark.org/security/wnpa-sec-2026-15.html
  - https://www.wireshark.org/security/wnpa-sec-2026-16.html
  - https://www.wireshark.org/security/wnpa-sec-2026-17.html
  - https://www.wireshark.org/security/wnpa-sec-2026-18.html
  - https://www.wireshark.org/security/wnpa-sec-2026-19.html
  - https://www.wireshark.org/security/wnpa-sec-2026-20.html
  - https://www.wireshark.org/security/wnpa-sec-2026-21.html
  - https://www.wireshark.org/security/wnpa-sec-2026-22.html
  - https://www.wireshark.org/security/wnpa-sec-2026-23.html
  - https://www.wireshark.org/security/wnpa-sec-2026-24.html
  - https://www.wireshark.org/security/wnpa-sec-2026-25.html
  - https://www.wireshark.org/security/wnpa-sec-2026-26.html
  - https://www.wireshark.org/security/wnpa-sec-2026-27.html
  - https://www.wireshark.org/security/wnpa-sec-2026-28.html
  - https://www.wireshark.org/security/wnpa-sec-2026-29.html
  - https://www.wireshark.org/security/wnpa-sec-2026-30.html
  - https://www.wireshark.org/security/wnpa-sec-2026-31.html
  - https://www.wireshark.org/security/wnpa-sec-2026-32.html
  - https://www.wireshark.org/security/wnpa-sec-2026-33.html
  - https://www.wireshark.org/security/wnpa-sec-2026-34.html
  - https://www.wireshark.org/security/wnpa-sec-2026-35.html
  - https://www.wireshark.org/security/wnpa-sec-2026-36.html
  - https://www.wireshark.org/security/wnpa-sec-2026-37.html
  - https://www.wireshark.org/security/wnpa-sec-2026-38.html
  - https://www.wireshark.org/security/wnpa-sec-2026-39.html
  - https://www.wireshark.org/security/wnpa-sec-2026-40.html
  - https://www.wireshark.org/security/wnpa-sec-2026-41.html
  - https://www.wireshark.org/security/wnpa-sec-2026-42.html
  - https://www.wireshark.org/security/wnpa-sec-2026-43.html
  - https://www.wireshark.org/security/wnpa-sec-2026-44.html
  - https://www.wireshark.org/security/wnpa-sec-2026-45.html
  - https://www.wireshark.org/security/wnpa-sec-2026-46.html
  - https://www.wireshark.org/security/wnpa-sec-2026-47.html
  - https://www.wireshark.org/security/wnpa-sec-2026-48.html
  - https://www.wireshark.org/security/wnpa-sec-2026-49.html
  - https://www.wireshark.org/security/wnpa-sec-2026-50.html
rules:
  - title: Detect Wireshark opening network capture files from untrusted locations
    description: Detects Wireshark opening network capture files from paths associated with downloads or temporary directories, which could indicate a user opening a malicious file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Wireshark execution without UI
    description: Detects Wireshark being executed with command-line arguments that suggest it's running without a user interface, which could be indicative of automated or malicious usage.
    platform: sigma
    severity: low
    tactics:
      - execution
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On April 30, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in Wireshark, a widely used network protocol analyzer. The vulnerabilities affect Wireshark versions 4.4.x prior to 4.4.15 and 4.6.x prior to 4.6.5. Successful exploitation of these vulnerabilities could lead to remote code execution (RCE), denial-of-service (DoS) conditions, and unauthorized disclosure of sensitive data. Given Wireshark's role in network analysis, these vulnerabilities pose a significant risk to organizations using the tool for monitoring and troubleshooting network traffic. These vulnerabilities highlight the importance of keeping software up to date, especially software that handles sensitive data.

## Attack Chain

1.  Attacker crafts a malicious network packet or capture file.
2.  The victim opens the malicious packet or capture file in a vulnerable version of Wireshark (4.4.x before 4.4.15 or 4.6.x before 4.6.5).
3.  Wireshark parses the packet or file using a vulnerable dissector.
4.  The vulnerable dissector fails to properly handle the malformed data, leading to a buffer overflow or other memory corruption issue.
5.  The memory corruption allows the attacker to overwrite critical program data or inject malicious code.
6.  The injected code is executed within the context of the Wireshark process.
7.  The attacker gains control of the Wireshark process.
8.  The attacker performs unauthorized actions, such as exfiltrating sensitive data or causing a denial-of-service condition.

## Impact

Successful exploitation of these vulnerabilities can have severe consequences, including remote code execution, potentially allowing an attacker to gain complete control over the affected system. A denial-of-service condition can disrupt network analysis activities and hinder incident response efforts. Data confidentiality can be compromised if an attacker gains access to sensitive network traffic data captured by Wireshark. The impact is significant for network administrators and security professionals who rely on Wireshark for network monitoring and analysis.

## Recommendation

*   Immediately upgrade Wireshark to version 4.4.15 or 4.6.5 or later to patch the vulnerabilities (refer to the Wireshark security advisories wnpa-sec-2026-08 through wnpa-sec-2026-50).
*   Implement network access controls to limit exposure of Wireshark instances to untrusted network traffic, reducing the likelihood of processing malicious packets.
*   Deploy the Sigma rule "Detect Wireshark opening network capture files from untrusted locations" to identify potential exploitation attempts.
*   Monitor systems running vulnerable versions of Wireshark for suspicious activity, such as unexpected process crashes or unauthorized network connections.
*   Consider using alternative packet analysis tools or sandboxing Wireshark for analyzing potentially malicious network traffic.
