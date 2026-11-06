---
brief_id: brief-2026-11-06-axis2-forced-browsing
event_id: brief-2026-11-06-axis2-forced-browsing
revision: 1
activity_at: "2026-11-06T19:22:53Z"
title: 'Apache Axis2/Java: Inconsistent enforcement of exposeServiceMetadata (CVE-2026-123779)'
slug: 2026-11-axis2-forced-browsing
description: Apache Axis2/Java contains a forced browsing vulnerability where the exposeServiceMetadata parameter is not enforced on specific routes, allowing unauthorized metadata disclosure.
date: "2026-11-06T19:22:53Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:apache:axis2:*:*:*:*:*:java:*:*
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Direct Request (Forced Browsing) vulnerability in Apache Axis2/Java.
    confidence_band: high
cves:
  - id: CVE-2026-123779
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/562
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache Axis2/Java to 2.0.2
      owner: IT Operations
      due: 48h
      evidence: Vulnerability addressed in Apache Axis2/Java 2.0.2.
  hunt_leads:
    - lead: Identify unauthorized access to WSDL or XSD files on Axis2 endpoints
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The exposeServiceMetadata parameter is not enforced on packaged .wsdl and .xsd file routes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Axis2/Java to version 2.0.2 or later
      owner: IT Operations
      addresses: CVE-2026-123779
      evidence: Vulnerability in Apache Axis2/Java before 2.0.2.
---

Apache Axis2/Java is vulnerable to forced browsing due to inconsistent enforcement of the exposeServiceMetadata configuration parameter. While the parameter is intended to disable metadata exposure, it fails to restrict access to packaged .wsdl and .xsd files, as well as the named-WSDL ?wsdl=NAME route in the standalone HTTP server. This vulnerability allows an attacker to retrieve service metadata even when explicitly disabled.

## Impact

The vulnerability may lead to unauthorized information disclosure of internal service configurations and API definitions, potentially aiding further reconnaissance of the target infrastructure.

## Recommendation

- Upgrade Apache Axis2/Java to version 2.0.2 or later to ensure the exposeServiceMetadata configuration is correctly enforced across all metadata endpoints.
- Review public-facing Axis2/Java instances to identify and restrict access to sensitive WSDL and XSD metadata routes until patches are applied.
