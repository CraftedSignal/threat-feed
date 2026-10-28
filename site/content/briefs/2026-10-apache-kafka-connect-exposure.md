---
brief_id: brief-2026-10-28-apache-kafka-connect-exposure
event_id: brief-2026-10-28-apache-kafka-connect-exposure
revision: 1
activity_at: "2026-10-28T18:21:14Z"
title: 'Apache Kafka: Configuration provider values exposed in Kafka Connect validation endpoint (CVE-2026-116593)'
slug: 2026-10-apache-kafka-connect-exposure
description: A vulnerability in the Kafka Connect configuration validation REST API allows an attacker to exfiltrate sensitive secrets intended to be resolved only at runtime.
date: "2026-10-28T18:21:14Z"
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
  validation_status: Needs environment validation of REST API access controls
cpes:
  - cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*
tags:
  - webserver
  - information-disclosure
  - cve-2026-116593
vendors:
  - Apache
products:
  - Kafka Connect (< 4.2.2)
  - Kafka Connect (>= 4.3.0, < 4.3.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker with access to the validation REST API endpoint can potentially exfiltrate sensitive configuration values that were intended to be hidden by Configuration Providers.
    confidence_band: high
cves:
  - id: CVE-2026-116593
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/423
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache Kafka Connect to 4.2.2 or 4.3.2
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-116593 remediation
  hunt_leads:
    - lead: Monitor for POST requests to /connector-plugins/*/config/validate
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability resides in /connector-plugins/{connector-type}/config/validate
  mitigation_plan:
    - priority: immediate
      action: Implement network segmentation or API gateway filtering to restrict access to the Kafka Connect REST API
      owner: IT Operations
      addresses: CVE-2026-116593
      evidence: Limiting access to the REST API prevents unauthenticated or unauthorized parties from exploiting the validation endpoint.
---

Apache Kafka Connect contains a flaw in the /connector-plugins/{connector-type}/config/validate REST API endpoint. This endpoint, intended for validating connector configurations, fails to properly protect sensitive configuration values handled by Configuration Providers. Consequently, an attacker with network access to the REST API can trigger the resolution of these secrets, causing them to be exposed in the validation response.

## Impact
Successful exploitation allows unauthorized disclosure of sensitive credentials or secrets stored within Configuration Providers, which were designed to remain masked until runtime.

## Recommendation
- Upgrade Apache Kafka Connect to version 4.2.2 or 4.3.2 to address CVE-2026-116593.
- Restrict network access to the Kafka Connect REST API to authorized administrative IP addresses only.
- Implement monitoring for excessive or anomalous requests to the /connector-plugins/ path.
