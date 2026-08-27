---
title: Unauthenticated Data Source Access in Baserow Application Builder
slug: 2026-08-baserow-auth-bypass
description: A vulnerability in Baserow's Application Builder allows unauthenticated attackers to bypass permission checks and retrieve sensitive data by leveraging improperly handled access control logic.
date: "2026-08-27T19:10:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - access-control-bypass
  - cve-2026-81335
vendors:
  - Baserow
products:
  - Baserow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The dispatch and record-name views in backend/src/baserow/contrib/builder/api/data_sources/views.py are declared with a permission class that admits any caller.
    confidence_band: high
cves:
  - id: CVE-2026-81335
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81335
rules:
  - title: Detect Potential Enumeration of Baserow Data Sources
    description: Detects potential exploitation attempts of CVE-2026-81335 by identifying high-frequency requests to data source endpoints using sequential integer identifiers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Baserow to version 2.3.1
      owner: IT Operations
      due: 24h
      evidence: Version 2.3.1 passes raise_exception to the same call.
  mitigation_plan:
    - priority: immediate
      action: Patch Baserow instance
      owner: IT Operations
      addresses: CVE-2026-81335
      evidence: NVD vulnerability disclosure
---

Baserow version 2.3.0 and earlier contain a critical authorization vulnerability (CVE-2026-81335) within the Application Builder component. The issue stems from the dispatch and record-name views in `backend/src/baserow/contrib/builder/api/data_sources/views.py`, which are configured with permission classes that do not restrict access to authenticated users. Furthermore, the `DataSourceService.dispatch_data_sources` function in `backend/src/baserow/contrib/builder/data_sources/service.py` fails to enforce the results of internal permission checks. 

Because the system continues execution regardless of the check result and uses the integration's internal credentials for the data source dispatch, an unauthenticated attacker can retrieve sensitive row and field information. Given that data source identifiers are small, sequential integers, an attacker can trivially enumerate these resources to exfiltrate data from multiple application builders within a target instance. This vulnerability was addressed in version 2.3.1.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass access controls and perform unauthorized data retrieval. By enumerating predictable integer IDs, an attacker can exfiltrate sensitive information from any data source accessible to the integration's internal service account. The impact includes potential large-scale data breach of application builder contents.

## Recommendation

- Upgrade all instances of Baserow to version 2.3.1 or higher immediately to apply the fix for CVE-2026-81335.
- Review web server access logs for anomalous, high-frequency GET or POST requests directed at `/api/builder/data-sources/` or `/api/builder/data-sources/record-name/` endpoints.
- Monitor for requests involving sequential integer IDs in URL parameters or request bodies as indicators of resource enumeration.
