---
brief_id: brief-2026-10-23-apache-camel-xxe
event_id: brief-2026-10-23-apache-camel-xxe
revision: 1
activity_at: "2026-10-23T13:38:47Z"
title: 'Apache Camel: XML External Entity Injection in Saxon Component (CVE-2026-90885)'
slug: 2026-10-apache-camel-xxe
description: The Apache Camel Saxon component is affected by an Improper Restriction of XML External Entity Reference vulnerability. The issue occurs when XQueryBuilder parses a message body that is already a javax.xml.transform.Source, causing the component to use Saxon's default parser settings, which resolve external entities.
date: "2026-10-23T13:38:47Z"
lastmod: "2026-10-26T15:45:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Apache Camel (org.apache.camel:camel-saxon) 4.0.0 before 4.18.5
  - Apache Camel (org.apache.camel:camel-saxon) 4.19.0 before 4.22.2
  - Apache Camel (4.0.0 <= 4.18.4, 4.19.0 <= 4.22.1)
cves:
  - id: CVE-2026-90885
    cvss: 7.5
    kev_status: "false"
references:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-90885
  - https://seclists.org/oss-sec/2026/q4/342
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90885
updates:
  - at: "2026-10-26T15:45:33Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90885
---

Apache Camel's `camel-saxon` component is vulnerable to an Improper Restriction of XML External Entity Reference vulnerability. In affected versions, the `XQueryBuilder` parses a message body that is already a `javax.xml.transform.Source` using Saxon's default parser settings, which results in the resolution of external entities declared in the body.
