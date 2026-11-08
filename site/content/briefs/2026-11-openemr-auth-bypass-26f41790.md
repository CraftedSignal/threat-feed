---
brief_id: brief-2026-11-08-openemr-auth-bypass-26f41790
event_id: brief-2026-11-08-openemr-auth-bypass-26f41790
revision: 1
activity_at: "2026-11-08T15:36:31Z"
title: 'OpenEMR: Missing authorization in portal onsite-document APIs (CVE-2026-124484)'
slug: 2026-11-openemr-auth-bypass-26f41790
description: OpenEMR versions prior to 8.4.0 contain a missing authorization flaw allowing authenticated users to access and modify cross-patient records by manipulating API parameters.
date: "2026-11-08T15:36:31Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.4.0)
cves:
  - id: CVE-2026-124484
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124484
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.4.0 or later
      owner: IT Operations
      due: 48h
      evidence: OpenEMR before 8.4.0 contains a missing authorization vulnerability
  hunt_leads:
    - lead: Identify API requests to portal onsite-document endpoints missing the patientId parameter
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Attackers can omit the patientId parameter and supply arbitrary record IDs
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to version 8.4.0 or later
      owner: IT Operations
      addresses: CVE-2026-124484
      evidence: OpenEMR before 8.4.0 contains a missing authorization vulnerability
---

OpenEMR versions before 8.4.0 contain an authorization vulnerability in the portal onsite-document API endpoints. The vulnerability allows an authenticated core user to access, list, read, or overwrite cross-patient documents, signatures, and template data. This is achieved by omitting the 'patientId' parameter from API requests and providing arbitrary record IDs.

## Impact

Successful exploitation results in unauthorized access to sensitive medical records and the ability to modify or overwrite patient document data and signatures, potentially leading to unauthorized data exposure and integrity loss.

## Recommendation

* Patch OpenEMR to version 8.4.0 or later immediately to remediate the authorization check flaw.
* Audit web server logs for requests to portal onsite-document API endpoints that lack a 'patientId' parameter.
