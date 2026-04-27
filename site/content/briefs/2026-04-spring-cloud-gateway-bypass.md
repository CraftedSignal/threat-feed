---
title: VMware Tanzu Spring Cloud Gateway Security Bypass Vulnerability
slug: 2026-04-spring-cloud-gateway-bypass
description: An anonymous, remote attacker can exploit a vulnerability in VMware Tanzu Spring Cloud Gateway to bypass security measures, potentially gaining unauthorized access or control.
date: "2026-04-13T10:12:40Z"
severities:
  - high
tags:
  - spring-cloud-gateway
  - security-bypass
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1212
    technique_name: Exploitation for Defense Evasion
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1041
rules:
  - title: Detect Suspicious Spring Cloud Gateway Bypass Attempts
    description: Detects potential attempts to bypass security measures in VMware Tanzu Spring Cloud Gateway via suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 1
---

A vulnerability exists in VMware Tanzu Spring Cloud Gateway that allows a remote, anonymous attacker to bypass security precautions. This vulnerability could potentially permit unauthorized access to protected resources, manipulation of data, or disruption of services. The advisory, released in April 2026, highlights the risk associated with unpatched instances of Spring Cloud Gateway. Organizations using this software should immediately investigate and apply necessary updates or mitigations to…
