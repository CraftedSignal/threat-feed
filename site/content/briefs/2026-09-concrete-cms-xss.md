---
title: Stored XSS in Concrete CMS Community Store
slug: 2026-09-concrete-cms-xss
description: An unauthenticated stored XSS vulnerability in Concrete CMS Community Store versions prior to 2.7.8 allows attackers to execute malicious scripts in manager sessions via order fields.
date: "2026-09-18T16:09:09Z"
lastmod: "2026-09-19T14:53:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:concretecms:community_store:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0D2F82E9-C0B9-5A1E-A8C0-A47810C7816C&utm_source=rss&utm_medium=rss
vendors:
  - Concrete CMS
products:
  - Community Store (< 2.7.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can store script payloads in billing name, email, or phone fields.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: renders customer-supplied order fields without HTML escaping... that execute in authenticated manager sessions.
    confidence_band: high
cves:
  - id: CVE-2026-93659
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93659
  - https://sploitus.com/exploit?id=0D2F82E9-C0B9-5A1E-A8C0-A47810C7816C&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Community Store to 2.7.8 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93659 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to 2.7.8
      owner: IT Operations
      addresses: CVE-2026-93659
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-19T14:53:37Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0D2F82E9-C0B9-5A1E-A8C0-A47810C7816C&utm_source=rss&utm_medium=rss
---

Concrete CMS Community Store versions before 2.7.8 are susceptible to a stored cross-site scripting (XSS) vulnerability due to improper input sanitization. The vulnerability exists because customer-supplied fields, specifically billing name, email, and phone, are rendered in the store's checkout and administrative interfaces without adequate HTML escaping. An unauthenticated attacker can exploit this flaw by submitting malicious JavaScript payloads through these fields during the order process. When an administrator or manager subsequently views the order details within the Concrete CMS dashboard, the malicious script executes within the context of the manager's authenticated session. This allows the attacker to perform unauthorized actions, including the creation of rogue administrative accounts or the exfiltration of sensitive order and customer data.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to hijack administrative sessions, leading to full site compromise, unauthorized administrative actions, and potential data exfiltration. Given that the Community Store is a core component for e-commerce functionality, the impact covers all Concrete CMS instances utilizing this plugin, potentially affecting the integrity and confidentiality of store transaction data and administrative controls.

## Recommendation

- Upgrade the Concrete CMS Community Store plugin to version 2.7.8 or later immediately.
- Implement a web application firewall (WAF) rule to block common XSS payloads in parameters associated with billing or checkout forms.
- Audit existing order records in the administrative console for suspicious script injection patterns in billing name, email, or phone fields.
