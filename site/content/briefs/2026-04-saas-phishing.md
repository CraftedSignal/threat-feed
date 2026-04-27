---
title: SaaS Notification Pipeline Phishing and Medusa Ransomware Exploitation
slug: 2026-04-saas-phishing
description: Threat actors are weaponizing legitimate SaaS notification pipelines to deliver phishing and spam emails, bypassing traditional email authentication protocols, and Storm-1175 is exploiting CVE-2026-1731 to deploy Medusa ransomware.
date: "2026-04-09T18:00:20Z"
severities:
  - high
tags:
  - saas
  - phishing
  - ransomware
  - medusa
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-1731
    cvss: 9.8
    epss: 0.81502
references:
  - https://blog.talosintelligence.com/the-threat-hunters-gambit/
  - https://blog.talosintelligence.com/weaponizing-saas-notification-pipelines/
  - https://www.darkreading.com/threat-intelligence/storm-1175-medusa-ransomware-high-velocity
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
rules:
  - title: Detect Coinminer via SHA256 Hash
    description: Detects the prevalent Coinminer malware based on its SHA256 hash.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief highlights two significant attack vectors observed by Cisco Talos. First, threat actors are exploiting legitimate SaaS notification pipelines (e.g., GitHub, Jira) to deliver phishing and spam, bypassing traditional email security measures by using a "Platform-as-a-Proxy" (PaaP) technique. This abuses the implicit trust placed in system-generated notifications from trusted enterprise tools, primarily targeting credential harvesting. Second, the Storm-1175 group is actively…
