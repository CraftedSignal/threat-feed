---
title: VMware Tanzu Spring Framework and Spring Security Vulnerabilities Allow Security Bypass
slug: 2025-03-vmware-spring-bypass
description: An anonymous, remote attacker can exploit multiple vulnerabilities in VMware Tanzu Spring Security and VMware Tanzu Spring Framework to bypass security measures.
date: "2026-03-24T10:36:02Z"
severities:
  - medium
tags:
  - vmware
  - spring
  - security-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Software
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2060
rules:
  - title: Detect Suspicious Process from Webserver
    description: Detects suspicious processes spawned by web server processes, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Spring Boot Actuator Endpoint Access
    description: Detects access to sensitive Spring Boot Actuator endpoints.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat involves the exploitation of vulnerabilities within VMware Tanzu Spring Framework and Spring Security. The specific vulnerabilities are not detailed in this brief, but their exploitation allows a remote, anonymous attacker to bypass existing security measures. This poses a risk to organizations utilizing these VMware Tanzu products, as attackers could potentially gain unauthorized access or escalate privileges within affected systems. Defenders should prioritize identifying and…
