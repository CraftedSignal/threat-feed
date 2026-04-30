---
title: Endian Firewall Command Injection Vulnerability (CVE-2026-34791)
slug: 2026-04-endian-firewall-rce
description: Endian Firewall version 3.3.25 and prior allows authenticated users to execute arbitrary OS commands due to an OS command injection vulnerability in the DATE parameter of the /cgi-bin/logs_proxy.cgi endpoint.
date: "2026-04-02T15:16:42Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34791
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34791
  - https://help.endian.com/hc/en-us/sections/360004371358-Community
  - https://www.vulncheck.com/advisories/endian-firewall-cgi-bin-logs-proxy-cgi-date-perl-command-injection
rules:
  - title: Detect Suspicious Logs Proxy Date Parameter
    description: Detects suspicious requests to /cgi-bin/logs_proxy.cgi with potentially malicious DATE parameters indicative of command injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Perl open() Call with Unvalidated Path
    description: Detects Perl open() calls with paths constructed from user-supplied input, which can indicate command injection vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Endian Firewall version 3.3.25 and prior is susceptible to OS command injection. This vulnerability, identified as CVE-2026-34791, allows authenticated users to execute arbitrary operating system commands. The vulnerability exists due to insufficient validation of the DATE parameter in the `/cgi-bin/logs_proxy.cgi` script. The DATE parameter's value is used to construct a file path that is subsequently passed to a Perl `open()` call. Due to an incomplete regular expression validation, an attacker can inject malicious commands. Successful exploitation allows the attacker to gain complete control of the affected system.

## Attack Chain

1.  An authenticated user accesses the `/cgi-bin/logs_proxy.cgi` endpoint.
2.  The attacker crafts a malicious `DATE` parameter containing OS commands to be injected.
3.  The `/cgi-bin/logs_proxy.cgi` script receives the `DATE` parameter.
4.  The script constructs a file path using the unvalidated `DATE` parameter.
5.  The script passes the crafted file path to a Perl `open()` call.
6.  The Perl `open()` function executes the injected OS commands due to the incomplete regular expression validation.
7.  The attacker gains arbitrary code execution on the system.
8.  The attacker can then perform actions such as installing malware, creating user accounts, or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary OS commands on the affected Endian Firewall system. This can lead to complete system compromise, including data theft, service disruption, and the potential to use the compromised system as a launchpad for further attacks within the network. Given that firewalls are critical security components, a compromise could have severe consequences for the entire network infrastructure, leading to widespread data breaches and significant financial losses.

## Recommendation

*   Apply available patches or upgrade to a supported version of Endian Firewall that addresses CVE-2026-34791 (refer to Endian Firewall's advisory).
*   Implement the Sigma rule `Detect Suspicious Logs Proxy Date Parameter` to detect potential exploitation attempts.
*   Monitor web server logs for suspicious requests to `/cgi-bin/logs_proxy.cgi` containing unusual characters or command-like syntax in the `DATE` parameter.
*   Implement strong input validation and sanitization for all user-supplied input to prevent command injection attacks.
