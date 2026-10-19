---
title: Apache Camel XML External Entity Injection via camel-xpath
slug: 2026-10-camel-xpath-xxe
description: An XML External Entity (XXE) vulnerability in the Apache Camel camel-xpath component allows attackers to trigger local file disclosure or server-side request forgery when documentType is set to InputSource.
date: "2026-10-19T15:07:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - xxe
  - vulnerability
  - apache
vendors:
  - Apache
products:
  - camel-xpath (< 4.18.5, 4.19.0 to 4.22.1)
  - camel-spring-boot (3.5.13)
  - camel-quarkus (3.29.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An external sender whose XML reaches such an expression could read files readable by the Camel process and cause the process to issue requests to hosts it names.
    confidence_band: high
cves:
  - id: CVE-2026-85250
    cvss: 7.5
references:
  - https://camel.apache.org/security/CVE-2026-85250.html
  - https://issues.apache.org/jira/browse/CAMEL-24475
  - https://sploitus.com/exploit?id=49FBD7E0-055E-5225-89EF-41D5FC45740E
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Apache Camel to 4.18.5, 4.22.1, or 4.23.0 across all environments.
      owner: IT Operations
      due: 24h
      evidence: Fixed Versions provided in vendor advisory.
  hunt_leads:
    - lead: Identify endpoints processing XML payloads that utilize Apache Camel XPath evaluation.
      technique_id: T1190
      data_needed:
        - Application dependency inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability is limited to specific usage of documentType=InputSource in XPathBuilder.
  mitigation_plan:
    - priority: immediate
      action: Disable use of InputSource documentType in XPathBuilder until patching is complete.
      owner: IT Operations
      addresses: CVE-2026-85250
      evidence: Mitigation advice provided in Apache Camel security advisory.
---

Apache Camel is vulnerable to XML External Entity (XXE) injection (CVE-2026-85250) within the `camel-xpath` component. The vulnerability exists when an XPath expression is configured with `documentType=InputSource`. Under this configuration, the `XPathBuilder` passes the XML input directly to `javax.xml.xpath`, which utilizes default JDK XML parser settings. This process bypasses the security hardening applied to Apache Camel’s default document type, allowing the parser to resolve `DOCTYPE` declarations and expand external entities. 

If an application processes untrusted XML using this configuration, an attacker can supply a malicious `DOCTYPE` to exfiltrate sensitive local files accessible by the service account or perform Server-Side Request Forgery (SSRF) against internal resources. Apache has released patches in versions 4.18.5, 4.22.1, and 4.23.0 to force `InputSource` inputs through the same hardened `DocumentBuilderFactory` used by the default document type.

## Attack Chain

1. An attacker identifies an application endpoint or service that processes user-supplied XML using Apache Camel's `camel-xpath` component.
2. The application is configured to use `.documentType(InputSource.class)` for XPath evaluation on the incoming XML stream.
3. The attacker crafts a malicious XML payload containing a `DOCTYPE` declaration with an external entity pointing to a local file or internal network resource (e.g., `&xxe;` referencing `/etc/passwd` or an internal API endpoint).
4. The XML payload is sent to the vulnerable service via an HTTP POST request or another XML-consuming interface.
5. The `XPathBuilder` processes the payload using the unhardened JDK default parser configuration.
6. The XML parser resolves the external entity and retrieves the contents of the local file or makes an outbound HTTP request from the server.
7. The application returns the results of the XPath evaluation, containing the exfiltrated file contents or the response from the targeted internal resource.

## Impact

Successful exploitation leads to unauthorized local file disclosure and potential server-side request forgery. This allows attackers to access sensitive system files, application configuration files, or internal network services that are otherwise protected by the network perimeter. The severity is rated as high due to the potential for full file system access within the context of the application process.

## Recommendation

1. Patch Apache Camel to version 4.18.5, 4.22.1, or 4.23.0 immediately as documented in the vendor security advisory.
2. For applications using Apache Camel Spring Boot or Quarkus, update to the versions that incorporate the fixed Camel library versions (e.g., camel-quarkus-xpath fixes released in CQ 3.40.0).
3. Audit codebase for explicit use of `.documentType(InputSource.class)` in `XPathBuilder` and replace with the default document type, which is already hardened against XXE.
4. Implement strict input validation and sanitization for all incoming XML data to prevent malicious `DOCTYPE` declarations.
