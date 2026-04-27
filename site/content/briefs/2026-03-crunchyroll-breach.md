---
title: Crunchyroll Data Breach via Telus Supply Chain Compromise
slug: 2026-03-crunchyroll-breach
description: Crunchyroll suffered a data breach after a Telus employee was phished, leading to Okta credential theft and exfiltration of 100GB of customer data.
date: "2026-03-24T12:00:00Z"
severities:
  - high
tags:
  - supply-chain
  - data-breach
  - credential-theft
  - phishing
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://x.com/IntCyberDigest/status/2035864555805413448
  - https://www.linkedin.com/feed/update/urn:li:activity:7441656561325924352/
ioc_counts:
  email: 1
rules:
  - title: Detect Anomalous Okta Login
    description: Detects Okta logins from unusual locations or IPs after a phishing attack and credential theft
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - okta
  - title: Detect Potential Data Exfiltration via Network Traffic
    description: Detects large outbound network traffic indicative of data exfiltration
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 23, 2026, a data breach was reported at Crunchyroll, stemming from a compromise of their outsourcing partner, Telus, in India. The attackers successfully gained access to Crunchyroll's environment after a Telus employee was targeted with a spoofed phishing email. This email delivered malware that stole the employee's Okta credentials, granting the attacker a foothold into Crunchyroll's systems. The breach resulted in the exfiltration of approximately 100 GB of sensitive customer…
