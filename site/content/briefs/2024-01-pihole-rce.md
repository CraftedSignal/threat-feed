---
title: Pi-hole FTL Remote Code Execution Vulnerability (CVE-2026-35519)
slug: 2024-01-pihole-rce
description: A remote code execution vulnerability exists in Pi-hole FTL versions 6.0 to before 6.6, where an authenticated attacker can inject arbitrary dnsmasq configuration directives through newline characters in the DNS host record configuration parameter, leading to command execution on the underlying system.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - pihole
  - rce
  - dnsmasq
  - cve-2026-35519
vendors:
  - Pi-hole
products:
  - Pi-hole
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35519
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35519
rules:
  - title: Detect Suspicious Dnsmasq Configuration Changes
    description: Detects modifications to dnsmasq configuration files that may indicate exploitation of CVE-2026-35519
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
  - title: Detect Script Execution via Dnsmasq
    description: Detects process creation events where the parent process is dnsmasq, indicating possible code execution from dnsmasq.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Pi-hole FTLDNS (pihole-FTL) versions 6.0 to before 6.6 are vulnerable to a Remote Code Execution (RCE) vulnerability, identified as CVE-2026-35519. This vulnerability resides in the DNS host record configuration parameter (dns.hostRecord) within the FTL engine. An authenticated attacker can exploit this flaw by injecting arbitrary `dnsmasq` configuration directives through newline characters. Successful exploitation enables the attacker to execute commands on the underlying Linux system. Pi-hole users running versions between 6.0 and 6.6 are affected and should upgrade to version 6.6 or later to remediate this vulnerability. This vulnerability poses a significant risk, potentially allowing attackers to compromise the Pi-hole server and gain unauthorized access to the network.

## Attack Chain

1.  The attacker authenticates to the Pi-hole web interface. This requires valid credentials or exploiting an authentication bypass.
2.  The attacker navigates to the DNS settings page within the web interface.
3.  The attacker locates the "Host record" configuration parameter (dns.hostRecord).
4.  The attacker injects malicious `dnsmasq` directives into the `dns.hostRecord` parameter, using newline characters to separate the injected code from legitimate configuration. For example, they might inject a directive to execute a shell command.
5.  The attacker saves the modified DNS settings, which triggers FTL to update the `dnsmasq` configuration.
6.  FTL processes the injected directives, leading to command execution on the underlying system. The injected directives are interpreted as part of the `dnsmasq` configuration.
7.  The attacker gains arbitrary code execution, potentially allowing them to install malware, modify system files, or pivot to other systems on the network.
8.  The attacker achieves complete control of the Pi-hole server, enabling them to intercept DNS traffic, redirect users to malicious websites, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-35519 allows an authenticated attacker to achieve arbitrary code execution on the Pi-hole server. This can lead to a full system compromise, allowing the attacker to install malware, steal sensitive data, or disrupt network services. Given Pi-hole's role as a DNS server, a successful attack could affect all devices on the network that rely on Pi-hole for DNS resolution. There is no information regarding the number of victims or specific sectors targeted.

## Recommendation

*   Upgrade Pi-hole FTL to version 6.6 or later to patch CVE-2026-35519.
*   Monitor Pi-hole logs for suspicious activity related to DNS settings modifications. Enable logging for web interface access attempts and configuration changes (reference: Pi-hole documentation).
*   Deploy the Sigma rule "Detect Suspicious Dnsmasq Configuration Changes" to identify potentially malicious modifications to the dnsmasq configuration file.
*   Implement strong authentication measures for the Pi-hole web interface to prevent unauthorized access. Use strong passwords and consider enabling multi-factor authentication where possible (reference: Pi-hole documentation).
