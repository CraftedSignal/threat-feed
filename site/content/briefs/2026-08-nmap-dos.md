---
title: Denial of Service Vulnerability in Nmap
slug: 2026-08-nmap-dos
description: A vulnerability in the Nmap network scanning tool allows a remote, anonymous attacker to trigger a Denial of Service condition by sending specially crafted packets.
date: "2026-08-12T10:17:43Z"
lastmod: "2026-08-17T14:54:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:nmap:nmap:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://www.exploit-db.com/exploits/52647
tags:
  - denial-of-service
  - vulnerability
  - network-scanning
vendors:
  - Nmap
products:
  - nmap
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in nmap ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2026-58058
    cvss: 6.5
    epss: 0.00278
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2787
  - https://www.exploit-db.com/exploits/52647
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Nmap on all systems to the latest available version.
      owner: IT Operations
      due: 72h
      evidence: General security best practice for resolving software vulnerabilities.
  mitigation_plan:
    - priority: short_term
      action: Identify and inventory systems running long-term Nmap scan processes.
      owner: Security Operations
      addresses: Nmap vulnerability
      evidence: Operational resilience planning.
updates:
  - at: "2026-08-17T14:54:07Z"
    level: L2
    summary: poc_available; added CVE-2026-58058
    sources:
      - exploit-db
    source_urls:
      - https://www.exploit-db.com/exploits/52647
---

The BSI has released an advisory regarding a Denial of Service (DoS) vulnerability affecting the Nmap network scanning tool. The flaw allows a remote, unauthenticated attacker to cause the application to crash or become unresponsive. This is likely triggered by processing malformed packets or unexpected network traffic during the scanning process. Given that Nmap is frequently used by security professionals and automated infrastructure, an exploit against a listening service or a system performing scans could lead to significant operational disruption in monitoring capabilities. Defenders should prioritize updating Nmap versions across all managed environments and identify internal systems utilizing the tool in persistent scanning configurations.

## Impact

Successful exploitation results in a Denial of Service, which effectively terminates the Nmap process. This impacts organizations relying on Nmap for continuous network discovery, vulnerability scanning, or automated security auditing. The scope includes any environment running vulnerable versions of Nmap on Windows, Linux, or macOS systems.

## Recommendation

* Monitor security advisories from the official Nmap project to identify the specific patched version.
* Update Nmap installations across the enterprise to the latest version provided by the vendor.
* Audit systems running Nmap in automated, persistent, or long-running scan modes to evaluate potential impact if these processes are interrupted.
* Review process-creation logs to identify systems where Nmap is currently executing in high-exposure or internet-facing network segments.
