---
title: Tenda HG3 Router Command Injection Vulnerability (CVE-2026-7096)
slug: 2024-01-tenda-hg3-command-injection
description: A command injection vulnerability (CVE-2026-7096) exists in the Tenda HG3 2.0 300003070 router, allowing remote attackers to execute arbitrary OS commands by manipulating the 'fmgpon_loid' argument in the 'formgponConf' function of the '/boaform/admin/formgponConf' file due to insufficient input validation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - router
  - tenda
vendors:
  - Tenda
products:
  - HG3 2.0 300003070
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7096
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7096
rules:
  - title: Detect Tenda HG3 Command Injection Attempt
    description: Detects potential command injection attempts targeting the Tenda HG3 router by monitoring HTTP POST requests to the 'formgponConf' endpoint with suspicious command-like strings in the 'fmgpon_loid' parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG3 Configuration File Access
    description: Detects access to the Tenda HG3 configuration file, which may indicate an attempt to exploit the command injection vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical command injection vulnerability, identified as CVE-2026-7096, affects Tenda HG3 2.0 300003070 routers. The vulnerability resides in the 'formgponConf' function within the '/boaform/admin/formgponConf' file. An attacker can exploit this flaw by manipulating the 'fmgpon_loid' argument. Successful exploitation allows a remote attacker to execute arbitrary operating system commands on the affected device. Given the public availability of an exploit, Tenda HG3 devices are at immediate risk of compromise. This poses a significant threat as attackers can potentially gain full control of the router, compromise connected networks, and exfiltrate sensitive information.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda HG3 2.0 300003070 router with an exposed web interface.
2.  The attacker crafts a malicious HTTP POST request targeting the '/boaform/admin/formgponConf' endpoint.
3.  The attacker injects a payload containing OS commands into the 'fmgpon_loid' parameter of the POST request.
4.  The Tenda HG3 router's web server processes the request without proper input validation of the 'fmgpon_loid' parameter.
5.  The injected OS command is executed by the router's operating system with the privileges of the web server process.
6.  The attacker gains remote code execution on the Tenda HG3 router.
7.  The attacker may establish a reverse shell to maintain persistent access or download further malicious payloads.
8.  The attacker can then pivot to internal networks, exfiltrate data, or use the compromised router for other malicious activities.

## Impact

Successful exploitation of CVE-2026-7096 grants attackers the ability to execute arbitrary OS commands on the Tenda HG3 router. This can lead to complete compromise of the device, allowing attackers to modify router settings, intercept network traffic, and potentially gain access to connected devices on the local network. Given the widespread use of Tenda routers in home and small business environments, a successful attack could impact thousands of users. The vulnerability's high CVSS score of 8.8 underscores the severity and potential for widespread damage.

## Recommendation

*   Deploy the Sigma rule "Detect Tenda HG3 Command Injection Attempt" to your SIEM to identify exploitation attempts by monitoring HTTP POST requests to '/boaform/admin/formgponConf' with suspicious commands in the 'fmgpon_loid' parameter.
*   Implement network intrusion detection system (NIDS) rules to detect malicious payloads in HTTP POST requests targeting the vulnerable endpoint, as described in the "Attack Chain" section.
*   While no specific IOCs are provided, analyze network traffic and web server logs for unusual activity originating from or targeting Tenda HG3 routers.
*   Monitor web server logs for HTTP POST requests to /boaform/admin/formgponConf (described in Attack Chain step 2).
