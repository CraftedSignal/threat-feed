---
title: SSRF Vulnerability in bitcoinj Payment Request Handler
slug: 2026-10-bitcoinj-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in the bitcoinj Payment Request Handler component allows remote attackers to perform unauthorized requests via manipulation of the pki_type argument.
date: "2026-10-16T00:41:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bitcoinj:bitcoinj:*:*:*:*:*:*:*:*
vendors:
  - bitcoinj
products:
  - bitcoinj (<= 0.17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument pki_type can lead to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-111210
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111210
action_plan:
  priority: elevated
  owners:
    - SOC
    - Application Security
  immediate_actions:
    - action: Inventory all applications using bitcoinj <= 0.17.
      owner: Application Security
      due: 48h
      evidence: CVE-2026-111210 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access for affected application servers to prevent SSRF exploitation.
      owner: IT Operations
      addresses: CVE-2026-111210
      evidence: NVD vulnerability details
---

A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in the bitcoinj library, affecting all versions up to and including 0.17. The flaw is located in the Payment Request Handler component, specifically within the `url.openConnection` function in `PaymentSession.java`. An attacker can exploit this vulnerability by manipulating the `pki_type` argument, which is not adequately sanitized before being used to open a network connection.

This vulnerability allows for remote exploitation, enabling an attacker to force the affected application to make arbitrary outbound HTTP requests. This can be leveraged to scan internal networks, interact with internal services that are not exposed to the public internet, or extract metadata from cloud environments. As of the time of reporting, the vulnerability has been publicly disclosed and is considered exploitable. No patch or vendor response is currently available.

## Impact

Successful exploitation of this SSRF vulnerability permits an attacker to perform requests on behalf of the application server. This can lead to unauthorized access to internal resources, exposure of sensitive infrastructure data, or potential pivoting into protected internal network segments. Organizations utilizing bitcoinj in backend systems or wallet services are at risk of unauthorized data exfiltration or service disruption if their applications are reachable by an unauthenticated attacker.

## Recommendation

Prioritize internal inventory assessment to identify applications leveraging bitcoinj 0.17 or earlier. 

- Restrict outbound network access from servers running bitcoinj to only required external endpoints.
- Implement strict ingress filtering and monitor for unusual outbound HTTP requests originating from application servers using this library.
- If immediate patching is not possible due to the lack of an official fix, consider implementing a Web Application Firewall (WAF) or application-layer input validation to sanitize the `pki_type` parameter before it is processed by the Payment Request Handler.
- Monitor logs for HTTP request patterns that deviate from standard wallet or payment request traffic.
