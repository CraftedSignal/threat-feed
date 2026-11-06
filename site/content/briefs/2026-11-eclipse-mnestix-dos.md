---
brief_id: brief-2026-11-06-eclipse-mnestix-dos
event_id: brief-2026-11-06-eclipse-mnestix-dos
revision: 1
activity_at: "2026-11-06T21:29:36Z"
title: 'Eclipse Mnestix AAS Generator: Denial of Service via parameter manipulation (CVE-2026-89295)'
slug: 2026-11-eclipse-mnestix-dos
description: The Eclipse Mnestix AAS Generator fails to enforce an upper bound on identifier generation parameters, allowing remote unauthenticated attackers to cause denial of service via excessive memory consumption.
date: "2026-11-06T21:29:36Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:eclipse:mnestix_aas_generator:*:*:*:*:*:*:*:*
vendors:
  - Eclipse Foundation
products:
  - Mnestix AAS Generator (0.1.0 <= version < 1.5.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote unauthenticated attacker can submit a large count to cause excessive memory consumption, potentially resulting in denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-89295
    cvss: 7.5
    epss: 0.00211
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89295
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch affected Mnestix AAS Generator instances to version 1.5.0
      owner: IT Operations
      due: 72h
      evidence: The vendor has released version 1.5.0 to address this vulnerability.
  hunt_leads:
    - lead: Search web server logs for requests to /api/v1/IdGenerator/submodelIds/ or /api/v2/IdGenerator/submodelIds/ containing excessively large integers in the path.
      technique_id: T1499
      data_needed:
        - Web server access logs (cs-uri-stem)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability is triggered by supplying a large count parameter in the specific URI paths.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block or rate-limit requests to IdGenerator endpoints with count parameters exceeding expected business thresholds
      owner: SOC
      addresses: CVE-2026-89295
      evidence: The issue is caused by a missing upper bound on the count parameter.
---

Eclipse Mnestix AAS Generator versions 0.1.0 through 1.4.x contain a vulnerability in the GET /api/v1/IdGenerator/submodelIds/{count} and GET /api/v2/IdGenerator/submodelIds/{count} endpoints. The application lacks an upper bound limit for the {count} parameter, causing the service to generate and hold an arbitrary number of identifiers in memory. Exploitation leads to a denial of service (DoS) due to memory exhaustion. Attackers require network access to the API and the ability to retrieve ID-generation configuration from the backend.

## Impact
Successful exploitation causes excessive memory consumption, which may result in a crash or service unavailability for the Mnestix AAS Generator instance.

## Recommendation
- Upgrade the Eclipse Mnestix AAS Generator to version 1.5.0 or later to ensure the count parameter is correctly validated and bounded.
- Implement rate limiting or request size validation at the API gateway or WAF level for the identified /api/v1/IdGenerator/submodelIds/ and /api/v2/IdGenerator/submodelIds/ endpoints.
- Audit logs for unusually high or erratic values in the {count} parameter segment of these URI paths.
