---
brief_id: brief-2026-11-02-linksys-router-auth-bypass
event_id: brief-2026-11-02-linksys-router-auth-bypass
revision: 2
activity_at: "2026-11-04T21:14:52Z"
revision_history:
  - revision: 2
    at: "2026-11-04T21:14:52Z"
    checksum: sha256:d41866fac93693ac22bea216d5128808c070ff7f17efe41c974dc839960fd0f8
    summary: added coverage for E5350 (1.0.00.037)
    changed_fields:
      - action_plan
      - affected_products
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121933
title: 'Linksys E5350: Authentication bypass in Setup Wizard (CVE-2026-121933)'
slug: 2026-11-linksys-router-auth-bypass
description: A critical authentication bypass vulnerability in the Linksys E5350 router allows remote, unauthenticated attackers to manipulate the wizard_router_pwd parameter via the /wizard/apply.cgi endpoint.
date: "2026-11-02T15:29:10Z"
lastmod: "2026-11-04T21:13:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: No vendor patch available; mitigation relies on network segmentation.
cpes:
  - cpe:2.3:o:linksys:e5350_firmware:1.0.00.037:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
vendors:
  - Linksys
products:
  - Linksys Router (unspecified version)
  - E5350 (1.0.00.037)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Linksys Router ausnutzen, um Administratorrechte zu erlangen.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument wizard_router_pwd can lead to missing authentication.
    confidence_band: high
cves:
  - id: CVE-2026-121933
    cvss: 10
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4276
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121933
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict access to the administrative web interface of all Linksys routers to authorized management VLANs only.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated access to administrator rights.
    - action: Restrict access to the management interface of all E5350 routers to authorized management subnets only
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated access
  hunt_leads:
    - lead: Monitor web management interface logs for anomalous POST/GET requests from external or unauthorized IP ranges.
      technique_id: T1068
      data_needed:
        - Firewall or gateway logs
        - HTTP management interface access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows remote unauthenticated access, which typically originates via the management interface.
    - lead: Identify HTTP POST or GET requests to /wizard/apply.cgi containing the wizard_router_pwd parameter
      technique_id: T1190
      data_needed:
        - Web server access logs or firewall/WAF logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability exists within the save_settings function of /wizard/apply.cgi via manipulation of the wizard_router_pwd argument
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable router management interfaces from internet-facing networks.
      owner: IT Operations
      addresses: Linksys Router
      evidence: Unpatched vulnerability allows remote exploitation.
    - priority: immediate
      action: Isolate affected devices from the public internet
      owner: IT Operations
      addresses: CVE-2026-121933
      evidence: No vendor patch available
updates:
  - at: "2026-11-04T21:13:21Z"
    level: L2
    summary: added coverage for E5350 (1.0.00.037)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121933
---

CVE-2026-121933 affects the Linksys E5350 router firmware version 1.0.00.037. The vulnerability resides in the Setup Wizard component, specifically within the `save_settings` function of the `/wizard/apply.cgi` script. Attackers can bypass authentication mechanisms by manipulating the `wizard_router_pwd` argument. Publicly available exploit code exists for this vulnerability, and the vendor has not provided a response or a patch to date.

## Impact

The vulnerability allows remote, unauthenticated attackers to gain unauthorized access or modify router settings. Given the nature of the authentication bypass, this could lead to full device compromise or administrative control.

## Recommendation

- Immediately restrict management interface access to the Linksys E5350 to trusted, internal IP ranges only.
- Disable the Setup Wizard functionality if the device is already provisioned and in use.
- Monitor network traffic for HTTP requests targeting `/wizard/apply.cgi` from untrusted or external source IPs.
- Because no patch is available, consider isolating vulnerable devices from the public internet using an upstream firewall or ACL.
