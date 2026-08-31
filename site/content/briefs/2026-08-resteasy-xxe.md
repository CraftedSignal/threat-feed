---
title: RESTEasy XML External Entity Vulnerability in SourceProvider
slug: 2026-08-resteasy-xxe
description: An XML External Entity (XXE) vulnerability in RESTEasy's SourceProvider allows unauthenticated attackers to perform arbitrary remote file reads via malicious XML input.
date: "2026-08-31T17:58:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:red_hat:resteasy:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xxe
  - vulnerability
vendors:
  - Red Hat
products:
  - RESTEasy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability allows an unauthenticated attacker to perform an unauthenticated remote file read.
    confidence_band: high
cves:
  - id: CVE-2026-17615
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17615
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rules to detect and block XML entities in application/xml traffic.
      owner: SOC
      due: 24h
      evidence: Source describes vulnerability as an XXE via crafted XML body.
  mitigation_plan:
    - priority: immediate
      action: Upgrade RESTEasy to the latest patched version.
      owner: IT Operations
      addresses: CVE-2026-17615
---

A vulnerability exists in the RESTEasy framework within the SourceProvider component, specifically affecting the writeTo() method. This flaw arises from the improper configuration of the SAXParser, which fails to disable the resolution of external entities when processing XML input. An unauthenticated attacker can exploit this by sending a specially crafted HTTP request containing an XML body with a malicious DOCTYPE declaration. 

When the application endpoint is designed to accept application/xml and processes the input using Source or StreamSource, the underlying SAXParser resolves the external entity defined in the malicious XML. This action forces the server to access and return the contents of local files on the system to the attacker in the HTTP response. Given that this requires no prior authentication, it poses a significant risk for unauthorized data exposure across any application utilizing the affected RESTEasy versions.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive local file contents from the host server. This vulnerability affects applications built using the RESTEasy framework, potentially leading to the compromise of configuration files, credentials, or other system-level data.

## Recommendation

Detection engineering teams should monitor web traffic for XML payloads containing DOCTYPE declarations directed at application endpoints. 

- Implement request body inspection on web application firewalls to identify and block incoming POST requests containing "DOCTYPE" or "ENTITY" keywords in the XML structure.
- Review application codebase to ensure that any use of SAXParser in SourceProvider-related implementations includes explicit configuration to disable DTD and external entity resolution.
- Update to the latest patched version of the RESTEasy framework as provided by the vendor.
