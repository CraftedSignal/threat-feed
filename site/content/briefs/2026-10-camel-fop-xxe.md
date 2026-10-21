---
brief_id: brief-2026-10-21-camel-fop-xxe
event_id: brief-2026-10-21-camel-fop-xxe
revision: 1
activity_at: "2026-10-21T11:19:20Z"
title: 'Apache Camel: camel-fop XML External Entity (XXE) injection (CVE-2026-91858)'
slug: 2026-10-camel-fop-xxe
description: The camel-fop component in Apache Camel is vulnerable to XXE injection when a third-party JAXP TransformerFactory is present, enabling local file disclosure and SSRF via maliciously crafted XSL-FO documents.
date: "2026-10-21T11:19:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against source advisory and CVE data.
tags:
  - xxe
  - vulnerability
  - java
vendors:
  - Apache
products:
  - camel-fop (< 4.18.5, >= 4.19.0 < 4.22.1)
  - Camel Quarkus (< 3.40.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'An external sender''s XSL-FO reaches a fop: producer, on a deployment that also has a third-party JAXP TransformerFactory on the classpath.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A DOCTYPE with an external subset declared in the XSL-FO body is then resolved while the body is transformed.
    confidence_band: high
cves:
  - id: CVE-2026-91858
    cvss: 6.5
    epss: 0.00359
    kev_status: "false"
references:
  - https://camel.apache.org/security/CVE-2026-91858.html
  - https://issues.apache.org/jira/browse/CAMEL-24605
  - https://sploitus.com/exploit?id=3CE21377-48D4-502A-9D07-BDC28010BE4A
  - https://sploitus.com/exploit?id=3CE21377-48D4-502A-9D07-BDC28010BE4A&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all applications utilizing Apache Camel camel-fop.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91858 impact scope
  mitigation_plan:
    - priority: immediate
      action: Upgrade camel-fop to 4.22.1 or 4.23.0.
      owner: IT Operations
      addresses: CVE-2026-91858
      evidence: Apache security advisory for CVE-2026-91858
---

Apache Camel's `camel-fop` component is affected by an XML External Entity (XXE) vulnerability (CVE-2026-91858) when a non-JDK `TransformerFactory` (e.g., Saxon-HE) is present on the application classpath. While `FopProducer` historically relied on `FEATURE_SECURE_PROCESSING`, this setting is insufficient to restrict external DTD and stylesheet access when using third-party JAXP providers. An attacker can supply a malicious XSL-FO document containing an external entity reference to perform Server-Side Request Forgery (SSRF) or read local files accessible to the application process.

## Impact

Successful exploitation allows for reading local files readable by the Camel process and conducting SSRF attacks against internal network resources.

## Recommendation

- Upgrade `camel-fop` to version 4.18.5, 4.22.1, or 4.23.0.
- Users of Camel Quarkus should update to version 3.40.0 or later to ensure the inclusion of the patched `camel-fop` version.
- If immediate patching is not possible, remove third-party `TransformerFactory` implementations (such as Saxon-HE) from the classpath to force the application to use the default JDK transformer, which safely handles secure processing.
- Ensure that untrusted XSL-FO input is not passed directly to a `fop:` producer endpoint.
