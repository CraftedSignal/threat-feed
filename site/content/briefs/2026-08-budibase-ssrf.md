---
title: CVE-2026-82241 SSRF Vulnerability in Budibase REST Datasource Preview
slug: 2026-08-budibase-ssrf
description: An SSRF vulnerability in Budibase backend-core allows authenticated users to bypass blacklist restrictions and perform requests against internal services in the 100.64.0.0/10 address range.
date: "2026-08-28T13:14:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Budibase
products:
  - backend-core
  - server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with the Builder permission can submit a REST datasource query preview request to POST /api/queries/preview targeting a reachable HTTP(S) service in the 100.64.0.0/10 range
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: causing the server to send a request to that target and return its response through the preview flow
    confidence_band: high
cves:
  - id: CVE-2026-82241
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82241
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update BLACKLIST_IPS environment variable to include 100.64.0.0/10
      owner: IT Operations
      due: 24h
      evidence: remediation is to add 100.64.0.0/10 to DEFAULT_BLACKLIST
  hunt_leads:
    - lead: Identify high-volume or suspicious POST requests to /api/queries/preview from Builder accounts
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker targets POST /api/queries/preview to exploit SSRF
  mitigation_plan:
    - priority: immediate
      action: Configure BLACKLIST_IPS
      owner: IT Operations
      addresses: CVE-2026-82241
      evidence: Remediation is to add 100.64.0.0/10 to DEFAULT_BLACKLIST
---

CVE-2026-82241 identifies an SSRF vulnerability within the Budibase backend-core library, which is a component of the Budibase server. The vulnerability stems from an incomplete blacklist configuration that fails to account for the CGNAT address range 100.64.0.0/10. When an administrator has not manually configured a custom `BLACKLIST_IPS` list, the application defaults to an inadequate set of restricted addresses. 

An authenticated attacker with 'Builder' permissions can exploit this by interacting with the `POST /api/queries/preview` endpoint. By submitting a crafted REST datasource query preview request, the attacker can force the Budibase server to perform an HTTP(S) request to arbitrary services within the 100.64.0.0/10 range. Because the preview functionality returns the response content to the user, this allows for sensitive data exfiltration or internal network reconnaissance. There is currently no vendor patch; the remediation requires manual configuration of the blacklist.

## Attack Chain

1. Attacker gains access to a Budibase instance with 'Builder' level permissions.
2. Attacker navigates to the REST datasource management interface to configure a new query.
3. Attacker identifies a target service residing within the internal 100.64.0.0/10 CGNAT range.
4. Attacker crafts a HTTP POST request to the `/api/queries/preview` endpoint with the target URL in the query body.
5. The Budibase server fails to validate the target URL against the restricted 100.64.0.0/10 range.
6. The backend server initiates an outbound request to the target internal service.
7. The internal service responds to the server request.
8. The Budibase server serializes the internal response and returns the data to the attacker via the UI/preview flow.

## Impact

Successful exploitation allows for unauthorized interaction with internal HTTP services that are intended to be protected from public or user-level access. This can lead to the exfiltration of sensitive information, unauthorized modification of internal state, or reconnaissance of the internal network architecture.

## Recommendation

* Immediately update the Budibase `BLACKLIST_IPS` environment variable to include the 100.64.0.0/10 range as specified in the advisory for CVE-2026-82241.
* Monitor access logs for `POST` requests to `/api/queries/preview` to identify potential abuse of the datasource preview feature by users with 'Builder' permissions.
* Restrict administrative 'Builder' access to only trusted personnel to mitigate the risk of account-based exploitation.
