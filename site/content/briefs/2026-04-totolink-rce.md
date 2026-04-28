---
title: Totolink N300RH OS Command Injection Vulnerability (CVE-2026-6158)
slug: 2026-04-totolink-rce
description: A remote OS command injection vulnerability exists in Totolink N300RH firmware version 6.1c.1353_B20190305 due to improper handling of the FileName argument in the setUpgradeUboot function, potentially allowing attackers to execute arbitrary commands.
date: "2026-04-13T05:17:44Z"
severities:
  - critical
tags:
  - cve
  - cve-2026-6158
  - command-injection
  - totolink
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6158
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6158
  - https://github.com/xyh4ck/iot_poc/tree/main/TOTOLINK/N300RHv4/02_setUpgradeUboot_RCE
  - https://vuldb.com/vuln/357038
rules:
  - title: Detect Totolink N300RH setUpgradeUboot Command Injection Attempt
    description: Detects potential command injection attempts in HTTP requests targeting the setUpgradeUboot function in Totolink N300RH devices.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple OS Command Injection Characters in URI Query
    description: Detects multiple OS command injection characters within a URI query string, indicative of a command injection attempt.
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

CVE-2026-6158 describes an OS command injection vulnerability affecting Totolink N300RH devices running firmware version 6.1c.1353_B20190305. The vulnerability lies within the `setUpgradeUboot` function of the `upgrade.so` file. By manipulating the `FileName` argument, a remote attacker can inject and execute arbitrary OS commands on the underlying system. Publicly available exploits exist, increasing the risk of exploitation. This vulnerability allows for complete compromise of the affected device, potentially leading to network pivoting, data exfiltration, or denial-of-service attacks. Given the widespread use of these devices, this vulnerability poses a significant risk to home and small business networks.

## Attack Chain

1. The attacker identifies a vulnerable Totolink N300RH device with firmware version 6.1c.1353_B20190305 exposed to the network.
2. The attacker crafts a malicious HTTP request targeting the `setUpgradeUboot` function within the `upgrade.so` library.
3. The crafted request includes a payload within the `FileName` argument designed to inject an OS command. The injected command could be simple, like `reboot`, or more complex, involving reverse shells or file downloads.
4. The device's web server processes the request and passes the manipulated `FileName` argument to the `setUpgradeUboot` function without proper sanitization.
5. The `setUpgradeUboot` function executes the injected OS command with the privileges of the web server process.
6. The attacker receives a reverse shell or observes other indications of successful command execution (e.g., device reboot).
7. The attacker leverages the compromised device for further malicious activities, such as pivoting to internal networks, exfiltrating sensitive data, or establishing persistence for long-term access.

## Impact

Successful exploitation of CVE-2026-6158 grants an attacker complete control over the affected Totolink N300RH device. This can lead to a number of severe consequences, including unauthorized access to the network the router is connected to, the theft of sensitive information transmitted through the network, and the potential to use the compromised device as a bot in a larger botnet. Given the number of potentially vulnerable devices, this vulnerability could have a significant impact, especially on home and small business networks.

## Recommendation

*   Monitor network traffic for requests to the `/upgrade.so` endpoint containing suspicious characters or command injection attempts in the `FileName` parameter, using a web application firewall (WAF) or intrusion detection system (IDS).
*   Deploy the Sigma rule provided below to detect command injection attempts in HTTP requests targeting the `upgrade.so` endpoint.
*   Unfortunately, there are no patches available, so consider replacing any Totolink N300RH devices running firmware version 6.1c.1353_B20190305.
