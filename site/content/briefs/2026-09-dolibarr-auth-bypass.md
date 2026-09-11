---
title: Authorization Bypass in Dolibarr Document Storage
slug: 2026-09-dolibarr-auth-bypass
description: An unauthenticated authorization bypass vulnerability in Dolibarr allows remote attackers to access arbitrary sensitive files via the document storage endpoints.
date: "2026-09-11T17:14:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dolibarr:dolibarr:23.0.4:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - authorization-bypass
vendors:
  - Dolibarr
products:
  - Dolibarr (23.0.4 - 24.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: By supplying a crafted hashp parameter value... gaining access to application logs, uploaded business documents, database backups
    confidence_band: high
cves:
  - id: CVE-2026-89013
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89013
rules:
  - title: Detects CVE-2026-89013 Exploitation - Unauthenticated File Access via hashp parameter
    description: Detects exploitation attempts where an unauthenticated user injects 'hashp=shared' into document endpoint queries to bypass authorization.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Dolibarr to version 24.0.1
      owner: IT Operations
      due: 24h
      evidence: Vendor release cycle for CVE-2026-89013
  hunt_leads:
    - lead: Search web logs for 'hashp=shared' in URI queries
      technique_id: T1083
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technical description of the authorization bypass
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 24.0.1 or later
      owner: IT Operations
      addresses: CVE-2026-89013
      evidence: NVD vulnerability disclosure
---

Dolibarr versions 23.0.4 through 24.0.0 contain an authorization bypass vulnerability (CVE-2026-89013) that enables unauthenticated remote attackers to retrieve arbitrary files from the application server. The vulnerability exists within the document storage handling logic found in htdocs/document.php and htdocs/viewimage.php. By supplying a crafted 'hashp=shared' parameter in an HTTP request, an attacker can trick the application into skipping necessary token validation checks. This allows the attacker to bypass access controls and satisfy the authorization conditions required to read sensitive data. Impacted files include application logs, confidential business documents, database backups containing password hashes, and files stored across different multicompany entities. This vulnerability is critical due to the potential for full database compromise and unauthorized exposure of business-critical information.

## Attack Chain

1. Attacker performs reconnaissance to identify the target Dolibarr instance.
2. Attacker crafts an HTTP GET or POST request targeting htdocs/document.php or htdocs/viewimage.php.
3. Attacker appends the 'hashp=shared' parameter to the URI query string to invoke the vulnerable code path.
4. The application processes the request, incorrectly bypassing the authentication token verification logic.
5. The application returns the requested file contents directly in the HTTP response body.
6. Attacker exfiltrates sensitive files, such as database backups or internal configuration logs.
7. Attacker uses credentials or metadata found in the exfiltrated files to escalate privileges or move laterally.

## Impact

Successful exploitation leads to unauthorized disclosure of sensitive business information. Potential impacts include access to database backups containing password hashes, sensitive configuration files, internal application logs, and documents shared across multiple company entities. This access can be used to gain complete control over the Dolibarr instance or to facilitate further attacks against the organization's broader infrastructure.

## Recommendation

1. Upgrade all instances of Dolibarr to version 24.0.1 or later to apply the official vendor patch.
2. Deploy the provided Sigma rule to detect exploitation attempts targeting the identified document endpoints.
3. Monitor web server logs for requests containing the 'hashp=shared' parameter string.
4. Conduct an audit of accessed files and user logs for unauthorized document retrieval following any identified exploitation attempts.
