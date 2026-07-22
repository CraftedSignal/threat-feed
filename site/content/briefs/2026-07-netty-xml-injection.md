---
title: Netty XML Injection Vulnerability (CVE-2026-56817)
slug: 2026-07-netty-xml-injection
description: A misconfiguration vulnerability (CVE-2026-56817) in Netty's XmlDecoder component allows attackers to send XML with DOCTYPE declarations to an unconfigured XML factory, potentially leading to XML External Entity (XXE) injection if the underlying Aalto XML parser resolves external entities, impacting Netty applications using `netty-codec-xml` versions 4.1.0.Final through 4.1.135.Final and 4.2.0.Final through 4.2.15.Final.
date: "2026-07-22T21:47:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - netty
  - xml
  - xxe
  - vulnerability
  - java
  - server-side
  - web-application
vendors:
  - Netty
products:
  - netty-codec-xml (4.1.0.Final - 4.1.135.Final)
  - netty-codec-xml (4.2.0.Final - 4.2.15.Final)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any caller that can deliver bytes to a Netty channel pipeline containing `XmlDecoder` can send XML with a DOCTYPE declaration to a parser instantiated with no security configuration
    confidence_band: high
cves:
  - id: CVE-2026-56817
references:
  - https://github.com/advisories/GHSA-4qhr-g3c6-fcfx
rules:
  - title: Detects CVE-2026-56817 Exploitation - HTTP POST with DOCTYPE Declaration
    description: Detects exploitation attempts against CVE-2026-56817 by identifying HTTP POST requests that contain XML with a DOCTYPE declaration, indicative of an XXE injection attempt against Netty's XmlDecoder component.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1589
    data_sources:
      - webserver
rules_count: 1
---

A high-severity misconfiguration vulnerability, tracked as CVE-2026-56817, exists within the `XmlDecoder` component of the Netty framework's `netty-codec-xml` library. This flaw allows any attacker capable of delivering bytes to a Netty channel pipeline containing `XmlDecoder` to send specially crafted XML. The vulnerability arises because the XML factory used by `XmlDecoder` can be instantiated without proper security configuration, enabling active Document Type Definition (DTD) and external entity handling. This permits the submission of XML payloads containing `DOCTYPE` declarations that refer to external entities, a common vector for XML External Entity (XXE) injection attacks. The exploitability is conditional, depending on whether the underlying Aalto XML parser resolves these external entities. Affected versions include `netty-codec-xml` from 4.1.0.Final up to and including 4.1.135.Final, and from 4.2.0.Final up to and including 4.2.15.Final. This vulnerability could lead to information disclosure, server-side request forgery (SSRF), or other impacts.

## Attack Chain

1. An attacker identifies a Netty-based application that accepts XML input and uses a vulnerable version of the `netty-codec-xml` library.
2. The attacker crafts a malicious XML payload containing a `<!DOCTYPE` declaration with an external entity reference (e.g., `<!ENTITY xxe SYSTEM "file:///path/to/sensitive/file">`).
3. The attacker sends this crafted XML payload, typically via an HTTP POST request, to the vulnerable Netty application's endpoint.
4. The Netty application's channel pipeline receives the input bytes and routes them to the `XmlDecoder` component for processing.
5. The `XmlDecoder` processes the XML using an underlying parser (such as Aalto XML) that has been instantiated with no security configuration, allowing it to handle DTDs and resolve external entities.
6. If the specific configuration and runtime behavior of the Aalto XML parser resolve external entities, the attacker-controlled external entity reference is processed.
7. This processing can lead to information disclosure (e.g., reading local files or internal network resources) or Server-Side Request Forgery (SSRF) if the entity points to remote URLs, impacting the confidentiality and integrity of the application.

## Impact

Successful exploitation of CVE-2026-56817 can lead to XML External Entity (XXE) injection, which primarily results in information disclosure. Attackers may be able to read arbitrary files on the vulnerable server, potentially exposing sensitive data, configuration files, or credentials. Depending on the server's network configuration and the capabilities of the XML parser, attackers might also be able to perform Server-Side Request Forgery (SSRF) to access internal network resources or external services, or initiate port scans. While the exploitability is conditional, affected organizations face a significant risk of data exfiltration and unauthorized access to internal systems if the vulnerable Netty applications are internet-facing or process untrusted XML input.

## Recommendation

* Patch CVE-2026-56817 by updating `netty-codec-xml` to a non-vulnerable version (e.g., 4.1.136.Final or 4.2.16.Final) immediately.
* Deploy the Sigma rule "Detects CVE-2026-56817 Exploitation - HTTP POST with DOCTYPE Declaration" to your SIEM to identify attempts at XXE injection.
* Enable comprehensive webserver logging to capture HTTP request bodies for analysis of XML payloads.
