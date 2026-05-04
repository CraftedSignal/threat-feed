---
title: DNS-over-HTTPS Enabled via Registry Modification
slug: 2024-01-dns-over-https-enabled
description: Detection of DNS-over-HTTPS (DoH) being enabled via registry modifications on Windows systems, potentially indicating defense evasion and obfuscation of network activity by masking DNS queries.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - dns-over-https
  - registry-modification
vendors:
  - Microsoft
  - Google
  - Mozilla
products:
  - Edge
  - Chrome
  - Firefox
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
  - https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_dns_over_https_enabled.toml
rules:
  - title: DNS-over-HTTPS Enabled via Edge Registry
    description: Detects the enabling of DNS-over-HTTPS in Microsoft Edge via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: DNS-over-HTTPS Enabled via Chrome Registry
    description: Detects the enabling of DNS-over-HTTPS in Google Chrome via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: DNS-over-HTTPS Enabled via Firefox Registry
    description: Detects the enabling of DNS-over-HTTPS in Mozilla Firefox via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

The use of DNS-over-HTTPS (DoH) can obscure network activity, potentially allowing malicious actors to bypass traditional DNS monitoring and conceal data exfiltration. When DoH is enabled, visibility into DNS query types, responses, and originating IPs is lost, hindering the detection of malicious activity. This behavior is detected by monitoring registry modifications associated with enabling DoH in popular browsers such as Microsoft Edge, Google Chrome, and Mozilla Firefox. The registry keys targeted are associated with settings that force the browsers to use secure DNS resolution, potentially circumventing organizational security policies.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a Windows system through various means, such as phishing or exploiting a software vulnerability.
2.  **Privilege Escalation (if necessary):** The attacker may need to escalate privileges to modify registry settings.
3.  **Defense Evasion:** The attacker modifies the Windows registry to enable DNS-over-HTTPS (DoH) in web browsers like Edge, Chrome, or Firefox. This is achieved by modifying specific registry keys such as `HKLM\SOFTWARE\Policies\Microsoft\Edge\BuiltInDnsClientEnabled`, `HKLM\SOFTWARE\Google\Chrome\DnsOverHttpsMode`, or `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`.
4.  **Obfuscation:** By enabling DoH, the attacker encrypts DNS queries, making it difficult for network monitoring tools to inspect DNS traffic.
5.  **Command and Control:** The attacker establishes command and control (C2) communication with a remote server over encrypted DNS traffic, evading traditional network-based detection methods.
6.  **Data Exfiltration:** The attacker uses the encrypted DNS channel to exfiltrate sensitive data, bypassing network security controls that rely on DNS inspection.
7.  **Persistence (Optional):** The attacker might establish persistence by ensuring the DoH settings remain enabled across system reboots.

## Impact

Successful exploitation leads to a loss of visibility into DNS traffic, hindering incident response and threat hunting efforts. Attackers can effectively hide command-and-control communications and data exfiltration activities. Although this activity by itself isn't inherently malicious, it removes a layer of defense, increasing the risk that malicious activities will go undetected.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect the enabling of DNS-over-HTTPS via registry modifications.
*   Enable Sysmon registry event logging to capture the necessary events for the provided Sigma rules to function effectively.
*   Review and update security policies to ensure DNS-over-HTTPS is only enabled through approved channels and for legitimate purposes, reducing the risk of misuse, and create exceptions in the detection rule for systems where this is a known requirement.
*   Investigate any alerts generated by the Sigma rules, focusing on identifying the user account, process, and associated network activity (reference the investigation guide in the source URL).
