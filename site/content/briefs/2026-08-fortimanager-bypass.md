---
brief_id: brief-2026-08-13-fortimanager-bypass
event_id: brief-2026-08-13-fortimanager-bypass
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:18e440736f85157dd02d7f0ec7d978cf0e471fb9d93853294a6b50f74379c3cf
    summary: exploited:true; KEV CVE-2024-47575
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Fortinet FortiManager Security Feature Bypass Vulnerability
slug: 2026-08-fortimanager-bypass
description: A remote, unauthenticated attacker can exploit a vulnerability in Fortinet FortiManager to bypass security controls, necessitating immediate monitoring of management interface traffic.
date: "2026-08-13T12:42:13Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2024-10-23T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Validated against public BSI advisory
cpes:
  - cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortimanager:7.6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortimanager_cloud:*:*:*:*:*:*:*:*
vendors:
  - Fortinet
products:
  - FortiManager
cves:
  - id: CVE-2024-47575
    cvss: 9.8
    epss: 0.94766
    kev: true
    kev_status: "true"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2814
  - https://nvd.nist.gov/vuln/detail/CVE-2024-47575
  - https://thehackernews.com/2026/10/attackers-exploit-fortios-flaw-to.html
  - https://www.securityweek.com/exploited-fortinet-bug-linked-to-stealthy-fortigate-implant-in-telecom-hack/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch FortiManager for CVE-2024-47575
      owner: IT Operations
      due: 24h
      evidence: Advisory requires remediation of vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via network ACLs
      owner: IT Operations
      addresses: CVE-2024-47575
      evidence: Public security advisory recommendation
updates:
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2024-47575
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

The German Federal Office for Information Security (BSI) has released a security advisory regarding a vulnerability in Fortinet FortiManager. This security feature bypass flaw allows a remote, unauthenticated attacker to circumvent established security measures. Given that FortiManager acts as a centralized management plane for Fortinet environments, this vulnerability carries significant risk for enterprise infrastructure. Defenders should monitor for unauthorized access attempts or anomalous behavior originating from network segments with access to the FortiManager management interface. Organizations using affected versions are urged to consult the official Fortinet PSIRT advisories to identify vulnerable firmware releases and implement necessary updates immediately.

## Impact

Successful exploitation of this vulnerability allows an unauthorized actor to bypass security mechanisms on the FortiManager appliance. This could lead to a loss of centralized oversight, unauthorized configuration changes, or further compromise of the managed network perimeter. The extent of potential damage includes full control over the management plane, which would enable the attacker to modify firewall rules, push malicious policies to downstream FortiGate devices, or exfiltrate sensitive configuration data.

## Recommendation

Prioritize patching for Fortinet FortiManager across all environments, specifically targeting the version ranges identified by Fortinet PSIRT associated with CVE-2024-47575. Restrict access to FortiManager management interfaces (typically ports 443, 8443, and 541) to known administrative subnets at the network level until patches are verified. Review logs for unexpected authentication requests or anomalies in administrative traffic patterns directed at the FortiManager web-based or CLI management endpoints.
