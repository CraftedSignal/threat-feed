---
title: Pre-Authentication XXE Vulnerability in SimpleSAMLphp
slug: 2026-08-simplesamlphp-xxe
description: A proof-of-concept exploit has been published for a pre-authentication XML External Entity (XXE) vulnerability in SimpleSAMLphp and the Saml2 Library, enabling arbitrary file read by unauthenticated remote attackers.
date: "2026-08-12T13:20:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - xxe
  - authentication
vendors:
  - SimpleSAMLphp
products:
  - SimpleSAMLphp
  - Saml2 Library
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Pre-auth XXE in SimpleSAMLphp allows arbitrary file read before authentication.
    confidence_band: high
cves:
  - id: CVE-2024-52806
    cvss: 8.3
    epss: 0.00414
  - id: CVE-2024-52596
    epss: 0.00985
references:
  - https://sploitus.com/exploit?id=16BEF64E-3CD4-5957-8FE7-21125AA498E3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SimpleSAMLphp and Saml2 Library instances.
      owner: IT Operations
      due: 24h
      evidence: Exploit code availability significantly increases risk.
  hunt_leads:
    - lead: Search for unauthorized file access patterns in web logs originating from external IPs.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Arbitrary file read capability allows attackers to target sensitive files.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules blocking XML external entities.
      owner: IT Operations
      addresses: CVE-2024-52806
      evidence: XXE vulnerability requires input filtering at the application boundary.
---

SimpleSAMLphp and the associated Saml2 Library have been identified as vulnerable to a pre-authentication XML External Entity (XXE) injection vulnerability, tracked as CVE-2024-52806 and CVE-2024-52596. This critical flaw permits an unauthenticated remote attacker to send maliciously crafted XML payloads to the application, which the parser processes to read arbitrary files from the underlying server filesystem. 

The vulnerability carries a CVSS score of 8.8, reflecting the ease of exploitation (low attack complexity, no authentication, no user interaction required). The availability of a functional Python-based proof-of-concept exploit, published on August 12, 2026, significantly increases the risk of exploitation for organizations running unpatched versions of the SimpleSAMLphp framework or utilizing the affected Saml2 Library components. Defenders should prioritize patching or implementing protective measures to prevent unauthorized access to sensitive configuration and credential files typically stored on these servers.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive server-side files, which may contain environment variables, encryption keys, application source code, or internal authentication credentials. This information disclosure can serve as a precursor to further system compromise, lateral movement, or full application takeover. All sectors utilizing SimpleSAMLphp for SAML identity federation are potentially exposed.

## Recommendation

* Immediately audit web server logs for HTTP requests containing XML payloads targeting SimpleSAMLphp endpoints.
* Update SimpleSAMLphp and the Saml2 Library to the latest patched versions provided by the vendor to remediate CVE-2024-52806 and CVE-2024-52596.
* Implement Web Application Firewall (WAF) rules to detect and block incoming POST requests containing prohibited XML external entity definitions (e.g., &lt;!ENTITY, SYSTEM, PUBLIC).
