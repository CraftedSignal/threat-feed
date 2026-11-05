---
brief_id: brief-2026-11-02-barracuda-advisory
event_id: brief-2026-11-02-barracuda-advisory
revision: 3
activity_at: "2026-11-05T22:16:48Z"
revision_history:
  - revision: 2
    at: "2026-11-04T15:03:07Z"
    checksum: sha256:2dfb5b25c3bb7dce47abdecae78b2c29e255188200243121649c255f6612b91f
    summary: added CVE-2026-111560 +1
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.ncsc.nl/alerts/kwetsbaarheden-in-barracuda-email-security-gateway-en-andere-producten-update-nu
  - revision: 3
    at: "2026-11-05T22:16:48Z"
    checksum: sha256:9ba2afbb6c4b254cf350efadd2af2c65d2997fd4a806e5a236e413a7ba03ac1d
    summary: severity → critical
    changed_fields:
      - action_plan
      - cpes
      - lastmod
      - references
      - severity
      - tags
      - updates
    source_urls:
      - https://www.reddit.com/r/netsec/comments/1xouqpj/barracuda_networks_is_your_new_best_friend/
title: 'Barracuda Networks: Pre-authentication Authorization Bypass and Command Injection'
slug: 2026-11-barracuda-advisory
description: Multiple Barracuda appliance products are affected by pre-authentication authorization bypass and command injection vulnerabilities that may allow unauthenticated remote attackers to execute arbitrary commands.
date: "2026-11-02T21:22:00Z"
lastmod: "2026-11-05T22:16:15Z"
type: advisory
claim_state: <nil>
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
  validation_status: Verified against Cyber Centre advisory.
cpes:
  - cpe:2.3:a:barracuda_networks:email_security_gateway:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-security
  - high-confidence-source
  - rce
  - email-security
vendors:
  - Barracuda Networks
products:
  - Email Security Gateway (< 9.4.0.030)
  - Load Balancer Application Delivery Controller (< 6.4.0)
  - Web Application Firewall (< 11.0.1)
  - Web Security Gateway (< 16.1.100.100)
  - Message Archiver (< 5.5.4.0)
  - WAF Control Center (< 2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerabilities are identified as pre-authentication authorization bypass and command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerabilities are identified as pre-authentication authorization bypass and command injection.
    confidence_band: high
cves:
  - id: CVE-2026-116606
    epss: 0.00728
    kev_status: "false"
  - id: CVE-2026-111560
    epss: 0.00471
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/barracuda-networks-security-advisory-av26-1112
  - https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-barracuda-email-security-gateway-en-andere-producten-update-nu
  - https://labs.watchtowr.com/barracuda-networks-is-your-new-best-friend-barracuda-email-security-gateway-pre-auth-remote-root-rce-cve-2026-116606-cve-2026-111560/
  - https://www.reddit.com/r/netsec/comments/1xouqpj/barracuda_networks_is_your_new_best_friend/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Apply firmware updates for all affected Barracuda appliances to the provided minimum version levels.
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory recommends updates for the listed products.
    - action: Inventory all Barracuda Email Security Gateway appliances
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects public-facing security appliances
  hunt_leads:
    - lead: Search Barracuda device administrative logs for unauthorized login attempts or abnormal administrative commands executed during the pre-authentication phase.
      technique_id: T1190
      data_needed:
        - Barracuda Appliance Audit Logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Advisory identifies pre-authentication vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to version 9.4.0.030 (ESG), 6.4.0 (ADC), 11.0.1 (WAF), 16.1.100.100 (WSG), 5.5.4.0 (BMA), or 2.2.1 (WCC).
      owner: IT Operations
      addresses: Barracuda appliance vulnerabilities
      evidence: Vendor security update requirements.
    - priority: immediate
      action: Patch Email Security Gateway to 9.4.0.030 or later
      owner: IT Operations
      addresses: CVE-2026-116606, CVE-2026-111560
      evidence: Root-level RCE vulnerability chain
updates:
  - at: "2026-11-04T15:02:27Z"
    level: L2
    summary: added CVE-2026-111560 +1
    sources:
      - ncsc-nl
    source_urls:
      - https://www.ncsc.nl/alerts/kwetsbaarheden-in-barracuda-email-security-gateway-en-andere-producten-update-nu
  - at: "2026-11-05T22:16:15Z"
    level: L3
    summary: severity → critical
    sources:
      - reddit-netsec
    source_urls:
      - https://www.reddit.com/r/netsec/comments/1xouqpj/barracuda_networks_is_your_new_best_friend/
---

Barracuda Networks has disclosed multiple security vulnerabilities affecting a wide range of its appliance products. The vulnerabilities are identified as pre-authentication authorization bypass and command injection. Unauthenticated remote attackers may be able to bypass security controls or execute arbitrary system commands on the affected devices. 

## Recommendation

Prioritize patching of all internet-facing Barracuda appliances to the following minimum versions:

* Barracuda Email Security Gateway (ESG): Update to 9.4.0.030 or later.
* Barracuda Load Balancer ADC: Update to 6.4.0 or later.
* Barracuda Web Application Firewall (WAF): Update to 11.0.1 or later.
* Barracuda Web Security Gateway (WSG): Update to 16.1.100.100 or later.
* Barracuda Message Archiver (BMA): Update to 5.5.4.0 or later.
* Barracuda WAF Control Center (WCC): Update to 2.2.1 or later.

Administrators should monitor appliance audit logs for unusual management interface access attempts or unexpected process execution spawned by web service accounts.
