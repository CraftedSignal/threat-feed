---
brief_id: brief-2026-11-08-openemr-auth-bypass-18ffda42
event_id: brief-2026-11-08-openemr-auth-bypass-18ffda42
revision: 1
activity_at: "2026-11-08T15:36:16Z"
title: 'OpenEMR: FHIR API authorization bypass (CVE-2026-124480)'
slug: 2026-11-openemr-auth-bypass-18ffda42
description: OpenEMR versions before 8.4.0 contain an authorization bypass vulnerability allowing authenticated users to exfiltrate cross-patient questionnaire data via the FHIR API.
date: "2026-11-08T15:36:16Z"
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
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.4.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: This allows unauthorized access to cross-patient QuestionnaireResponse data, leading to the potential exfiltration of sensitive protected health information.
    confidence_band: high
cves:
  - id: CVE-2026-124480
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124480
rules:
  - title: Detect CVE-2026-124480 Exploitation - Unauthorized FHIR API Access
    description: Detects exploitation of CVE-2026-124480 by identifying requests to the FHIR QuestionnaireResponse endpoint that include the suspicious APICSRFTOKEN header.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.4.0
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation
  hunt_leads:
    - lead: Analyze web server logs for GET /fhir/QuestionnaireResponse requests associated with unusual account activity or unexpected use of APICSRFTOKEN
      technique_id: T1537
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploitation involves the use of the APICSRFTOKEN header to access QuestionnaireResponse data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.4.0
      owner: IT Operations
      addresses: CVE-2026-124480
      evidence: Vendor patch
---

OpenEMR versions prior to 8.4.0 contain an authorization bypass vulnerability in the FHIR API implementation. Authenticated users with low privileges can bypass FHIR scope restrictions by reusing the 'api_csrf_token_js' value from a session in an 'APICSRFTOKEN' HTTP header. This enables unauthorized access to cross-patient 'QuestionnaireResponse' data, leading to the potential exfiltration of sensitive protected health information (PHI) via the 'GET /fhir/QuestionnaireResponse' endpoint.

## Impact

Successful exploitation allows low-privileged users to exfiltrate site-wide PHI contained within FHIR QuestionnaireResponse objects, bypassing existing scope controls.

## Recommendation

- Upgrade to OpenEMR 8.4.0 or later to remediate the authorization logic in the FHIR API.
- Audit access logs for the 'GET /fhir/QuestionnaireResponse' endpoint to identify patterns of unauthorized enumeration by low-privileged accounts.
