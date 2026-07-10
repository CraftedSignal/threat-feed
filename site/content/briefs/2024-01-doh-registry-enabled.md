---
title: DNS-over-HTTPS Enabled via Registry Modification
slug: 2024-01-doh-registry-enabled
description: Detection of DNS-over-HTTPS (DoH) being enabled via registry modifications on Windows systems, potentially indicating defense evasion by masking network activity and hindering traditional DNS monitoring.
date: "2024-01-02T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - windows
  - dns-over-https
vendors:
  - Microsoft
  - Google
  - Mozilla
products:
  - Microsoft Edge
  - Google Chrome
  - Mozilla Firefox
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.tenforums.com/tutorials/151318-how-enable-disable-dns-over-https-doh-microsoft-edge.html
  - https://chromeenterprise.google/policies/?policy=DnsOverHttpsMode
rules:
  - title: DNS-over-HTTPS Enabled in Microsoft Edge via Registry
    description: Detects when DNS-over-HTTPS is enabled in Microsoft Edge via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
    data_sources:
      - registry_set
      - windows
  - title: DNS-over-HTTPS Enabled in Google Chrome via Registry
    description: Detects when DNS-over-HTTPS is enabled in Google Chrome via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
    data_sources:
      - registry_set
      - windows
  - title: DNS-over-HTTPS Enabled in Mozilla Firefox via Registry
    description: Detects when DNS-over-HTTPS is enabled in Mozilla Firefox via registry modification.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers may enable DNS-over-HTTPS (DoH) to encrypt DNS queries, bypassing traditional DNS monitoring and hindering an organization's visibility into network traffic. This can be used to hide internet activity, facilitate data exfiltration, or mask command-and-control communications. This activity can be identified by monitoring registry modifications associated with enabling DoH in popular web browsers such as Microsoft Edge, Google Chrome, and Mozilla Firefox. The detection focuses on changes to specific registry keys related to the configuration of DoH functionality. While DoH can improve privacy, its malicious use poses a defense evasion risk. The rule specifically detects registry changes associated with enabling DoH in Edge, Chrome, and Firefox, indicating potential misuse for defense evasion.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via phishing or exploiting a vulnerability).
2.  Attacker executes code (e.g., PowerShell script or executable) on the target system.
3.  The code modifies the Windows Registry to enable DNS-over-HTTPS (DoH) in a web browser.
4.  Specific registry keys are targeted, such as `HKLM\SOFTWARE\Policies\Microsoft\Edge\BuiltInDnsClientEnabled`, `HKLM\SOFTWARE\Google\Chrome\DnsOverHttpsMode`, or `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`.
5.  The registry values are set to enable DoH (e.g., setting `BuiltInDnsClientEnabled` to 1 in Edge).
6.  The web browser starts using DoH, encrypting DNS queries and sending them over HTTPS.
7.  This hides the DNS queries from traditional network monitoring tools.
8.  The attacker uses the DoH-enabled browser to conduct malicious activities, such as data exfiltration or command-and-control communication, without being easily detected.

## Impact

Successful exploitation allows attackers to bypass traditional DNS monitoring, masking malicious network activity. This can lead to undetected data exfiltration, command and control, or other malicious behavior. The impact is reduced visibility for security teams and increased dwell time for attackers. The severity is low as DoH can be a legitimate configuration, so further investigation is needed.

## Recommendation

*   Deploy the Sigma rules provided to detect registry modifications associated with enabling DNS-over-HTTPS (DoH) and tune for your environment.
*   Investigate any detected instances of DoH being enabled via registry modifications, correlating with other security events to assess legitimacy.
*   Monitor the relevant registry paths (`*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled`, `*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode`, `*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS`) for unexpected changes.
*   Review and update security policies to ensure that DNS-over-HTTPS is only enabled through approved channels and for legitimate purposes.
