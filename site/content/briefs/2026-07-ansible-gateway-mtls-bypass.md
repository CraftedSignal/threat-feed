---
title: 'CVE-2026-18141: mTLS Bypass in Ansible Automation Platform'
slug: 2026-07-ansible-gateway-mtls-bypass
description: An unauthenticated remote attacker can bypass mTLS authentication in the aap-gateway component of Event-Driven Ansible to inject arbitrary events and trigger automated workflows.
date: "2026-07-31T17:39:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-18141
  - authentication-bypass
  - automation
vendors:
  - Red Hat
products:
  - Ansible Automation Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can bypass mutual Transport Layer Security (mTLS) authentication for event streams.
    confidence_band: high
cves:
  - id: CVE-2026-18141
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18141
---

A high-severity vulnerability, tracked as CVE-2026-18141, affects the aap-gateway component of Red Hat Ansible Automation Platform's Event-Driven Ansible (EDA). The flaw enables an unauthenticated remote attacker to bypass mutual Transport Layer Security (mTLS) authentication when communicating with event streams. By manipulating the target event stream URL and forging the HTTP Subject header, an attacker can successfully authenticate as a trusted source. 

The exploitation process is further aided by an information disclosure issue within the gateway, which returns the expected certificate subject in error messages during failed connection attempts. This allows attackers to identify the required Subject string for header forgery. Successful exploitation allows for the injection of arbitrary events into the EDA system, which can result in the execution of unauthorized automated workflows. This poses a significant risk to organizations using EDA for automated infrastructure or application management.

## Impact

Successful exploitation allows unauthenticated attackers to inject arbitrary events into the Event-Driven Ansible system. This can lead to the unauthorized triggering of automated workflows, which may involve system configuration changes, service restarts, or other administrative actions configured within the EDA platform. The impact includes potential loss of integrity for automated processes and unauthorized manipulation of managed infrastructure.

## Recommendation

1. Patch the Ansible Automation Platform environment to the version provided by Red Hat that addresses CVE-2026-18141.
2. Review webserver logs for the aap-gateway component to identify anomalous requests, specifically looking for high frequencies of 401 or 403 errors that may indicate an attacker probing for the required certificate subject.
3. Restrict network access to the EDA gateway endpoint to trusted source IP addresses to limit the exposure of the management interface to the public internet.
