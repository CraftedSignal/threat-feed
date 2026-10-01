---
title: Unauthenticated Information Disclosure in FileRise Pro
slug: 2026-10-filerise-disclosure
description: An unauthenticated information disclosure vulnerability in the FileRise Pro portal endpoint allows attackers to retrieve sensitive configuration data, including internal storage paths and client contact information.
date: "2026-10-01T20:26:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - api-security
  - reconnaissance
vendors:
  - FileRise
products:
  - FileRise Pro (< 3.24.0)
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The endpoint returns the full internal record of a FileRise Pro client portal including internal storage folder paths.
    confidence_band: high
references:
  - https://github.com/error311/FileRise/security/advisories/GHSA-m49m-9v4m-w2rq
  - https://sploitus.com/exploit?id=BA50BC57-ADB3-5D5C-B767-FFDB3541D672
rules:
  - title: Detect FileRise Pro Information Disclosure Attempt (CVE-2026-104110)
    description: Detects unauthorized GET requests to the FileRise Pro portal endpoint get.php, which is indicative of exploitation of CVE-2026-104110.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update FileRise Pro to version 3.24.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor fix announcement for CVE-2026-104110
  hunt_leads:
    - lead: Search logs for multiple 200 OK responses to get.php with unique slugs
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint returns portal record upon valid slug
  mitigation_plan:
    - priority: immediate
      action: Upgrade FileRise Pro to v3.24.0
      owner: IT Operations
      addresses: CVE-2026-104110
      evidence: Vendor remediation statement
---

FileRise Pro versions prior to 3.24.0 contain an unauthenticated information disclosure vulnerability within the `public/api/pro/portals/get.php` endpoint. The vulnerability exists because the endpoint fails to invoke the `fr_pro_guard_auth()` authentication check used by sibling endpoints. Consequently, any unauthenticated user who identifies a valid portal slug - a non-secret, human-readable identifier - can query this endpoint to receive a full record of the portal's configuration. 

Exposed data includes the server's internal storage folder path, client contact emails, and detailed upload policy constraints (e.g., file extension whitelists, upload limits). This information provides significant reconnaissance value to an attacker by mapping the application's internal structure and identifying targets for subsequent exploitation attempts against file-handling functionalities. The vendor has released a patch in version 3.24.0, which mandates session-based authentication for this endpoint.

## Attack Chain

1. Attacker identifies a target application instance running FileRise Pro.
2. Attacker obtains or guesses a valid portal slug (e.g., from public email correspondence or open-source intelligence).
3. Attacker crafts an unauthenticated HTTP GET request to the target URL: `https://<target>/api/pro/portals/get.php?slug=<guessed_slug>`.
4. The application processes the request in `PortalController::getPortalBySlug()` without invoking authentication guards.
5. The server serializes and returns the complete portal configuration record, including sensitive internal paths and PII.
6. Attacker harvests the disclosed internal storage paths and business policy details.
7. Attacker utilizes the reconnaissance data to conduct further probes against file upload or download functionalities within the environment.

## Impact

Successful exploitation results in the disclosure of internal metadata, including server-side directory structures, client PII, and security policy details. While the vulnerability does not directly permit remote code execution or file modification, the exposure of internal paths and upload constraints facilitates further reconnaissance and targeted exploitation of the file-processing infrastructure. All FileRise deployments with the Pro add-on configured are affected.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Update all FileRise Pro instances to version 3.24.0 or later to ensure the authentication guard is correctly enforced.
- Audit web server access logs for anomalous GET requests to `public/api/pro/portals/get.php` originating from unauthorized or non-standard sources.
- Implement monitoring for attempts to access internal API endpoints that typically require authentication.
- Ensure that internal directory structures disclosed by this vulnerability are not used to inform further security hardening or segmentation efforts.
