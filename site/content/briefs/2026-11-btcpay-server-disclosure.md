---
brief_id: brief-2026-11-05-btcpay-server-disclosure
event_id: brief-2026-11-05-btcpay-server-disclosure
revision: 1
activity_at: "2026-11-05T22:32:52Z"
title: 'BTCPay Server: LND node macaroon information disclosure (CVE-2026-119757)'
slug: 2026-11-btcpay-server-disclosure
description: BTCPay Server versions prior to 2.4.2 are vulnerable to an unauthenticated information disclosure flaw allowing remote attackers to steal LND node macaroon files for full administrative control and fund theft.
date: "2026-11-05T22:32:52Z"
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
  validation_status: Source verified; patch available.
cpes:
  - cpe:2.3:a:btcpayserver:btcpayserver:*:*:*:*:*:*:*:*
tags:
  - cve-2026-119757
  - information-disclosure
  - cryptocurrency
  - vulnerability
vendors:
  - BTCPay Server
products:
  - BTCPay Server (< 2.4.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The flaw allows remote attackers to access .macaroon credential files associated with the Lightning Network Daemon (LND).
    confidence_band: high
cves:
  - id: CVE-2026-119757
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119757
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade BTCPay Server to version 2.4.2 or later.
      owner: IT Operations
      due: 24h
      evidence: BTCPay Server versions prior to 2.4.2 are vulnerable.
  hunt_leads:
    - lead: Identify unauthorized access to internal BTCPay Server paths related to LND configuration or macaroon files.
      technique_id: T1552.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated remote attackers can retrieve .macaroon credential files.
  mitigation_plan:
    - priority: immediate
      action: Upgrade BTCPay Server to version 2.4.2 or later.
      owner: IT Operations
      addresses: CVE-2026-119757
      evidence: BTCPay Server versions prior to 2.4.2 are vulnerable.
---

BTCPay Server versions prior to 2.4.2, including 2.4.2 release candidates, are susceptible to an information disclosure vulnerability. The flaw permits an unauthenticated remote attacker to retrieve '.macaroon' credential files utilized by the Lightning Network Daemon (LND).

## Impact

Successful exploitation results in full administrative control over the affected LND node. Attackers may perform unauthorized operations, including the movement and theft of funds from the affected Lightning node deployments.

## Recommendation

- Upgrade BTCPay Server to version 2.4.2 or later immediately to remediate the vulnerability.
- Audit LND node configurations for unauthorized access or unexpected changes in node management patterns if the instance was exposed to the internet.
- Review network access controls to ensure the BTCPay Server management interface is not accessible to untrusted network segments.
