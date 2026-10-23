---
brief_id: brief-2026-10-23-kruize-autotune-auth-bypass
event_id: brief-2026-10-23-kruize-autotune-auth-bypass
revision: 1
activity_at: "2026-10-23T19:50:52Z"
title: 'Kruize Autotune: REST API authentication bypass and credential exposure (CVE-2026-110975)'
slug: 2026-10-kruize-autotune-auth-bypass
description: Kruize Autotune contains an authentication bypass in its REST API that exposes sensitive monitoring datasource credentials in cleartext via improperly serialized JSON responses.
date: "2026-10-23T19:50:52Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-supported threat; requires environment-specific network posture review.
cpes:
  - cpe:2.3:a:kruize:autotune:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - credential-exposure
  - webserver
  - cve-2026-110975
vendors:
  - Kruize
products:
  - Autotune
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: As a result, the authentication secrets stored for each configured monitoring datasource (basic-auth passwords, bearer tokens, API keys, and OAuth2 client secrets) were returned in cleartext to any client able to reach the service.
    confidence_band: high
cves:
  - id: CVE-2026-110975
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110975
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the Kruize Autotune REST API to trusted management subnets.
      owner: IT Operations
      due: 24h
      evidence: An attacker with network access to Autotune could harvest these credentials.
  hunt_leads:
    - lead: Monitor web server access logs for anomalous GET requests to /datasources or datasource-metadata from unauthorized internal or external IP addresses.
      technique_id: T1552.001
      data_needed:
        - Web server access logs (source IP, requested URL, response status code)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoints that return datasource configuration... /datasources and the datasource-metadata endpoint.
  mitigation_plan:
    - priority: immediate
      action: Implement network-level access controls to the Kruize Autotune API endpoints.
      owner: IT Operations
      addresses: CVE-2026-110975
      evidence: Its REST API ships without an authentication layer.
---

A vulnerability in Kruize Autotune (CVE-2026-110975) allows unauthenticated users to access sensitive datasource configuration details. Specifically, the endpoints '/datasources' and 'datasource-metadata' fail to implement authentication checks. Due to insecure default Gson serialization settings, the application returns datasource objects containing plain-text secrets, including basic-auth passwords, bearer tokens, API keys, and OAuth2 client secrets. An attacker with network reach to the Autotune API can retrieve these credentials to gain unauthorized access to the connected monitoring stack.

## Impact
Successful exploitation results in the unauthorized disclosure of cleartext credentials used to access connected monitoring systems. This impact is limited to the credentials managed and stored within the Kruize Autotune datasource configuration.

## Recommendation
- Inventory all Kruize Autotune deployments and restrict network access to the REST API to trusted IP ranges only via network segmentation or firewall rules.
- Audit the monitoring stack for any anomalous access or credential usage following potential exposure via the Autotune service.
- Monitor for and apply vendor-provided security patches once available to remediate the insecure API endpoints and serialization logic.
