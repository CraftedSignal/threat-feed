---
title: Snipe-IT Information Disclosure and IDOR Vulnerability
slug: 2026-08-snipe-it-idor
description: An authenticated attacker can exploit an information disclosure and IDOR vulnerability (CVE-2026-55694) in Snipe-IT to leak and download confidential, restricted EULA documents belonging to other users.
date: "2026-08-19T22:33:41Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Snipe-IT
products:
  - Snipe-IT
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: By targeting specific user IDs through the API, an attacker can bypass file-name randomization and access confidential documents belonging to other users.
    confidence_band: high
cves:
  - id: CVE-2026-55694
references:
  - https://github.com/advisories/GHSA-3hgv-jr5j-cg9x
  - https://github.com/grokability/snipe-it/commit/f15d78621b003be30ac114ba68626683894935ef
rules:
  - title: Detect CVE-2026-55694 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-55694 where an account-based path is used to retrieve stored EULA files.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Snipe-IT instances to v8.6.3
      owner: IT Operations
      due: 24h
      evidence: Fixed in https://github.com/grokability/snipe-it/commit/f15d78621b003be30ac114ba68626683894935ef
  hunt_leads:
    - lead: Search web logs for high frequency of requests to /api/v1/users/*/eulas
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Step 2 of reproduction chain involves calling /api/v1/users/{target_id}/eulas.
---

Snipe-IT versions prior to 8.6.3 are susceptible to a chained vulnerability involving information disclosure and Insecure Direct Object Reference (IDOR). The vulnerability, identified as CVE-2026-55694, allows an authenticated user to bypass security controls designed to protect sensitive files. By querying the Snipe-IT API for EULA associations of arbitrary user accounts, an attacker can obtain the randomized, secret filenames of EULA documents stored on the server. Although the primary file retrieval endpoint correctly enforces access controls, an alternative profile-based route fails to validate authorization, allowing the attacker to download these confidential documents belonging to other users. This flaw poses a significant risk to the confidentiality of organizational documentation managed within the Snipe-IT asset management platform.

## Attack Chain

1. Attacker authenticates to the Snipe-IT application as a standard, restricted user.
2. Attacker sends an authorized GET request to the API endpoint /api/v1/users/{target_id}/eulas.
3. The application returns the internal, randomized filename (e.g., eula-xxx.pdf) of the EULA assigned to the target user.
4. Attacker attempts to access the file via the main endpoint GET /stored-eula-file/{filename}, which is intercepted by security controls returning a 403 Forbidden.
5. Attacker pivots to the vulnerable route GET /account/stored-eula-file/{filename}.
6. The server fails to perform authorization checks on the account-based file retrieval route.
7. The server processes the request and returns a 200 OK with the target user's confidential EULA file.
8. Attacker successfully exfiltrates the sensitive document.

## Impact

Successful exploitation allows unauthorized access to private, signed EULA files stored within the Snipe-IT instance. This can lead to the exposure of personally identifiable information (PII) or sensitive contractual agreements, impacting the confidentiality of all users registered in the system.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Update all instances of Snipe-IT to version 8.6.3 or later to remediate CVE-2026-55694.
- Enable web server access logging to capture full HTTP request paths for analysis.
- Deploy log monitoring for HTTP 200 OK responses originating from /account/stored-eula-file/ where the requesting user session does not align with the ownership of the accessed object.
- Review web server logs for high volumes of GET requests to /api/v1/users/ targeting varying numeric user IDs, which may indicate enumeration activity related to this IDOR.
