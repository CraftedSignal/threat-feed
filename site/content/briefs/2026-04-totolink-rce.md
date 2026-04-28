---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6116)
slug: 2026-04-totolink-rce
description: CVE-2026-6116 is an OS command injection vulnerability in Totolink A7100RU version 7.4cu.2313_b20191024, allowing remote attackers to execute arbitrary OS commands by manipulating the 'ip' argument in the setDiagnosisCfg function of the /cgi-bin/cstecgi.cgi CGI handler, with a public exploit available.
date: "2026-04-12T05:16:01Z"
severities:
  - critical
tags:
  - cve-2026-6116
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6116
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6116
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_181/README.md
  - https://vuldb.com/vuln/356976
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability (CVE-2026-6116) by monitoring for suspicious requests to the /cgi-bin/cstecgi.cgi endpoint with shell metacharacters in the query string.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Command Injection via Web Logs
    description: This rule detects potential command injection attempts in Totolink A7100RU routers by analyzing web server logs for requests to the /cgi-bin/cstecgi.cgi endpoint containing specific patterns indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, CVE-2026-6116, has been identified in Totolink A7100RU router firmware version 7.4cu.2313_b20191024. The vulnerability resides within the CGI handler component, specifically in the `setDiagnosisCfg` function of the `/cgi-bin/cstecgi.cgi` file. An attacker can remotely exploit this vulnerability by manipulating the `ip` argument, injecting arbitrary OS commands that are then executed by the router's operating system. The public availability of the exploit increases the risk of widespread exploitation. This vulnerability poses a significant threat to affected devices, allowing attackers to gain complete control and potentially compromise entire networks.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The crafted request includes the `ip` argument within the `setDiagnosisCfg` function.
4.  The attacker injects an OS command within the `ip` argument, such as using backticks or shell metacharacters.
5.  The router's CGI handler processes the request and executes the injected OS command.
6.  The attacker gains remote code execution on the router with the privileges of the web server process.
7.  The attacker can then use this access to modify router settings, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-6116 grants a remote attacker complete control over the affected Totolink A7100RU router. This can lead to a variety of malicious outcomes, including the installation of backdoors, modification of DNS settings for phishing attacks, and the potential to use the compromised router as part of a botnet. Given the high CVSS score (9.8), the impact is considered critical. While specific numbers of victims and sectors targeted are not provided, the vulnerability's ease of exploitation and the router's widespread use make it a significant concern for home and small business networks.

## Recommendation

*   Deploy the Sigma rules provided to detect exploitation attempts targeting the `/cgi-bin/cstecgi.cgi` endpoint (Sigma rule: "Detect Totolink A7100RU Command Injection Attempt").
*   Monitor web server logs for suspicious requests containing shell metacharacters in the `cs-uri-query` field to identify potential exploitation attempts (Sigma rule: "Detect Totolink A7100RU Command Injection via Web Logs").
*   Implement network intrusion detection systems (IDS) rules to identify and block malicious traffic patterns associated with this vulnerability.
*   Consider implementing web application firewall (WAF) rules to filter out malicious requests targeting the vulnerable endpoint.
