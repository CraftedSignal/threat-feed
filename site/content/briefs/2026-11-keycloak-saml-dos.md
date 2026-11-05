---
brief_id: brief-2026-11-05-keycloak-saml-dos
event_id: brief-2026-11-05-keycloak-saml-dos
revision: 1
activity_at: "2026-11-05T18:22:43Z"
title: 'Keycloak: SAML XML processing denial of service (CVE-2026-107123)'
slug: 2026-11-keycloak-saml-dos
description: An unauthenticated remote attacker can cause a denial of service in Keycloak by sending crafted SAML requests with malicious dateTime or duration values that trigger excessive CPU consumption.
date: "2026-11-05T18:22:43Z"
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
  - cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - saml
  - authentication
  - webserver
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: OS Exhaustion Flood
    evidence: An unauthenticated remote attacker can exploit this by sending specially crafted SAML requests to the server, leading to high CPU utilization and a denial of service for all users.
    confidence_band: high
cves:
  - id: CVE-2026-107123
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107123
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all instances of Keycloak in the production environment
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107123 impacts the SAML XML processing component of Keycloak
  hunt_leads:
    - lead: Identify abnormal spikes in CPU usage associated with SAML XML parsing activity
      technique_id: T1499.001
      data_needed:
        - Keycloak server CPU metrics
        - Web server logs detailing request volume and source IP
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Excessive CPU consumption by the XML parser
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for Keycloak as released by Red Hat
      owner: IT Operations
      addresses: CVE-2026-107123
      evidence: NVD advisory confirms vulnerability in SAML XML processing
---

A vulnerability in the SAML XML processing component of Keycloak allows an unauthenticated remote attacker to trigger a denial of service (DoS) condition. The vulnerability arises from improper validation of XML dateTime or duration strings. When a specially crafted SAML request containing excessively long values is processed, the XML parser consumes high levels of CPU, potentially leading to service unavailability for all users.

## Impact

Successful exploitation results in high CPU utilization and a denial of service, preventing legitimate users from accessing authentication services provided by the affected Keycloak instance.

## Recommendation

- Identify all internet-facing or SAML-enabled Keycloak instances within the environment.
- Monitor for available patches from Red Hat to address CVE-2026-107123.
- Implement rate limiting and request size restrictions for endpoints handling SAML authentication requests.
- Review web application firewall logs for high-frequency or anomalous XML/SAML requests.
