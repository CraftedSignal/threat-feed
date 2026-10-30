---
brief_id: brief-2026-10-23-apache-camel-xxe
event_id: brief-2026-10-23-apache-camel-xxe
revision: 3
activity_at: "2026-10-30T04:30:44Z"
revision_history:
  - revision: 2
    at: "2026-10-30T02:29:34Z"
    checksum: sha256:7152fb53a1aa5f9f34fb7ac44c694e66b9a6e48388f24a5e1dbade3822784f71
    summary: added coverage for Apache Camel (< 4.14.8, 4.18.3, 4.21.0)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - qa_status
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-49099&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-10-30T04:30:44Z"
    checksum: sha256:223bc1d1ff6a2e45bb889dd546691bffc6edc034746c2e1e2165698073b252c7
    summary: severity → critical; added CVE-2026-40860
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-40860&utm_source=rss&utm_medium=rss
title: 'Apache Camel: XML External Entity Injection in Saxon Component (CVE-2026-90885)'
slug: 2026-10-apache-camel-xxe
description: The Apache Camel Saxon component is affected by an Improper Restriction of XML External Entity Reference vulnerability. The issue occurs when XQueryBuilder parses a message body that is already a javax.xml.transform.Source, causing the component to use Saxon's default parser settings, which resolve external entities.
date: "2026-10-23T13:38:47Z"
lastmod: "2026-10-30T04:29:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch versions confirmed by vendor advisory
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:camel:4.19.0:*:*:*:*:*:*:*
tags:
  - apache-camel
  - rce
  - deserialization
  - cve-2026-40860
vendors:
  - Apache
products:
  - Apache Camel (org.apache.camel:camel-saxon) 4.0.0 before 4.18.5
  - Apache Camel (org.apache.camel:camel-saxon) 4.19.0 before 4.22.2
  - Apache Camel (4.0.0 <= 4.18.4, 4.19.0 <= 4.22.1)
  - Apache Camel (< 4.14.8, 4.18.3, 4.21.0)
  - Apache Camel (3.0.0-4.14.6)
  - Apache Camel (4.15.0-4.18.1)
  - Apache Camel (4.19.0-4.19.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated HTTP client overrides the route scoped SOQL/SOSL/Apex parameters via unfiltered headers
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: Unsafe deserialization of JMS ObjectMessage in camel-jms via getObject() enabling RCE.
    confidence_band: high
cves:
  - id: CVE-2026-90885
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-49099
    cvss: 5.3
    epss: 0.0052
    kev_status: "false"
  - id: CVE-2026-40860
    cvss: 9.8
    epss: 0.01739
    kev_status: "false"
references:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-90885
  - https://seclists.org/oss-sec/2026/q4/342
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90885
  - https://camel.apache.org/security/CVE-2026-49099.html
  - https://github.com/apache/camel/pull/23887
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-49099
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-49099&utm_source=rss&utm_medium=rss
  - https://camel.apache.org/security/CVE-2026-40860.html
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-40860
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-40860&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
    - Application Security
  immediate_actions:
    - action: Patch Apache Camel to 4.14.8 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-49099 advisory
    - action: Patch Apache Camel installations to 4.14.7, 4.18.2, or 4.20.0.
      owner: IT Operations
      due: 24h
      evidence: Recommended Fix in advisory.
  hunt_leads:
    - lead: Inspect web access logs for incoming HTTP requests containing unexpected header keys such as sObjectQuery, apexUrl, or sObjectName
      technique_id: T1190
      data_needed:
        - Web server access logs
        - WAF request header logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves unfiltered headers bypassing HttpHeaderFilterStrategy
    - lead: Identify applications using Camel JMS consumers with mapJmsMessage=true (default) and external-facing or shared message brokers.
      technique_id: T1059.003
      data_needed:
        - Application configuration files (Camel routes, jms component configuration)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attack vector relies on default configuration of mapJmsMessage=true and reachable JMS destinations.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Gateway to drop or sanitize requests containing headers associated with camel-salesforce
      owner: IT Operations
      addresses: CVE-2026-49099
      evidence: Unfiltered headers allow parameter injection at the HTTP boundary
    - priority: immediate
      action: Implement -Djdk.serialFilter and configure JMS provider trust policies.
      owner: Infrastructure
      addresses: CVE-2026-40860
      evidence: Advisory notes full protection requires JVM-level and provider-level filters.
updates:
  - at: "2026-10-26T15:45:33Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90885
  - at: "2026-10-30T02:28:50Z"
    level: L2
    summary: added coverage for Apache Camel (< 4.14.8, 4.18.3, 4.21.0)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-49099&utm_source=rss&utm_medium=rss
  - at: "2026-10-30T04:29:49Z"
    level: L3
    summary: severity → critical; added CVE-2026-40860
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OSCERD-CVE-2026-40860&utm_source=rss&utm_medium=rss
---

Apache Camel's `camel-saxon` component is vulnerable to an Improper Restriction of XML External Entity Reference vulnerability. In affected versions, the `XQueryBuilder` parses a message body that is already a `javax.xml.transform.Source` using Saxon's default parser settings, which results in the resolution of external entities declared in the body.
