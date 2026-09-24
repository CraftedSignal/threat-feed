---
title: XXE Vulnerability in http4s-scala-xml
slug: 2026-09-http4s-xxe
description: The http4s-scala-xml library is vulnerable to XML External Entity (XXE) attacks due to improper configuration of the SAXParserFactory, allowing unauthenticated attackers to perform SSRF or local file disclosure.
date: "2026-09-24T20:04:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:http4s:http4s_scala_xml:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - xxe
  - cve-2026-61741
vendors:
  - http4s
products:
  - http4s-scala-xml (<= 0.24.0)
  - http4s-scala-xml (>= 1.0.0-M1, <= 1.0.0-M38.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that uses these decoders to parse untrusted XML is vulnerable to XML External Entity (XXE) attacks.
    confidence_band: high
cves:
  - id: CVE-2026-61741
    cvss: 9.3
references:
  - https://github.com/advisories/GHSA-cjx3-73hr-rpw7
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade http4s-scala-xml to latest version
      owner: IT Operations
      due: 24h
      evidence: Patched versions address the SAXParserFactory configuration
  mitigation_plan:
    - priority: immediate
      action: Override ElemInstances#saxFactory to harden the parser
      owner: Security Engineering
      addresses: CVE-2026-61741
      evidence: Workaround documentation provided in source
---

The http4s-scala-xml library (versions <= 0.24.0 and 1.0.0-M1 through 1.0.0-M38.1) contains a critical XML External Entity (XXE) vulnerability identified as CVE-2026-61741. The issue stems from the use of an unhardened `javax.xml.parsers.SAXParserFactory` within the library's `EntityDecoder`. Because the parser is initialized without explicit security constraints, it defaults to processing DOCTYPE declarations, external general/parameter entities, and DTDs.

An unauthenticated remote attacker can exploit this by submitting malformed XML payloads to an application leveraging these decoders. If successfully exploited, this allows the attacker to read arbitrary local files accessible to the service, conduct server-side request forgery (SSRF) against internal services, or trigger a denial-of-service condition via excessive entity expansion. This vulnerability affects any Scala application utilizing the library for processing untrusted XML inputs.

## Impact

Successful exploitation allows for the exfiltration of sensitive local files from the application server, unauthorized interaction with internal network resources (SSRF), and system instability through resource exhaustion. This impacts any environment using http4s-scala-xml to process user-supplied XML data.

## Recommendation

* Upgrade to a non-vulnerable version of http4s-scala-xml immediately.
* If an upgrade is not immediately feasible, override the `ElemInstances#saxFactory` with a hardened configuration that explicitly disables DTD loading and external entity processing using the `javax.xml.parsers.SAXParserFactory` feature flags (e.g., `http://apache.org/xml/features/disallow-doctype-decl`).
* Implement input validation for any XML endpoints to detect and reject payloads containing `DOCTYPE` declarations.
* Audit application logs for abnormal outgoing network traffic from the web service process, which may indicate attempted SSRF exploitation via CVE-2026-61741.
