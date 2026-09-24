---
title: Stored XSS in Snipe-IT Uploaded Files API
slug: 2026-09-snipe-it-xss
description: Snipe-IT contains a stored XSS vulnerability in the uploaded-files API due to the failure to apply safe-inline allowlists to XML documents, allowing authenticated attackers to execute arbitrary JavaScript in the victim's session context via CVE-2026-63498.
date: "2026-09-24T20:07:51Z"
lastmod: "2026-09-24T20:08:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:snipe_it:snipe_it:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cve-2026-63498
  - web-vulnerability
  - privilege-escalation
vendors:
  - Snipe-IT
products:
  - Snipe-IT (< 8.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack requires an authenticated account with file access to at least one supported object.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: An attacker can execute arbitrary JavaScript in the Snipe-IT origin when a victim opens the malicious attachment URL.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A user with the customfields.create permission can store HTML/JS in a Custom Field name, which is later rendered as an asset-list column title.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An account holding ONLY customfields.create planted a payload that, when a superuser opened /hardware, issued an authenticated request in that session and granted the attacker's own account the superuser permission.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who knows a victim's password fully bypasses that account's 2FA and obtains a persistent token with full API access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078.004
    technique_name: Valid Accounts
    evidence: The token is long-lived (40-year expiry by default) and grants full API access as the user.
    confidence_band: high
cves:
  - id: CVE-2026-63498
    cvss: 8.7
references:
  - https://github.com/advisories/GHSA-396x-xmvh-p563
  - https://github.com/grokability/snipe-it/commit/e929b31f0b183c5810bd2b833c1f6f643cbe5284
  - https://github.com/advisories/GHSA-p9h3-gvpq-5539
  - https://github.com/grokability/snipe-it/commit/58754e4e3b86b58a0c4523012ef04a2ae990d2c8
  - https://github.com/advisories/GHSA-hxcx-9h4f-42xx
  - https://github.com/snipe/snipe-it/pull/19294
rules:
  - title: Detect Suspicious Personal Access Token Creation
    description: Detects potential exploitation of CVE-2026-63493 by monitoring for API requests to generate personal access tokens, which should be correlated with authentication logs showing incomplete 2FA.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1550.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Snipe-IT to version 8.7.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Fixed in https://github.com/grokability/snipe-it/commit/e929b31f0b183c5810bd2b833c1f6f643cbe5284
  mitigation_plan:
    - priority: immediate
      action: Upgrade Snipe-IT to 8.7.0
      owner: IT Operations
      addresses: CVE-2026-63498
      evidence: 'Affected Packages: composer/snipe/snipe-it (vulnerable: < 8.7.0)'
updates:
  - at: "2026-09-24T20:08:14Z"
    level: L2
    summary: added coverage for Snipe-IT (< 8.7.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-p9h3-gvpq-5539
  - at: "2026-09-24T20:08:24Z"
    level: L2
    summary: 'added detection rule: Detect Suspicious Personal Access Token Creation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-hxcx-9h4f-42xx
---

Snipe-IT is vulnerable to stored cross-site scripting (XSS) via its uploaded-files API (CVE-2026-63498). The vulnerability exists because the API endpoint `GET /api/v1/{object_type}/{id}/files/{file_id}` honors an attacker-controlled `inline=true` query parameter for all uploaded files without verifying the safety of the content. While the non-API web controller correctly utilizes `StorageHelper::allowSafeInline()` to sanitize inline responses, the API controller fails to perform this check.

An authenticated user with permission to upload files can upload a malicious XSLT stylesheet and an XML document that references it via the `xml-stylesheet` instruction. When a victim views the XML file through the API with the `inline=true` parameter, the browser parses the XSLT and executes the embedded JavaScript within the context of the Snipe-IT origin. This allows the attacker to perform unauthorized actions on behalf of the victim, access sensitive information, or escalate privileges if a superuser is targeted. The vulnerability was reproduced in versions prior to 8.7.0.

## Attack Chain

1. Attacker authenticates to the Snipe-IT instance with a user account permitted to upload files to at least one object.
2. Attacker prepares a malicious XSLT file containing an embedded payload (e.g., `<script>...</script>`).
3. Attacker uses the API `POST /api/v1/{object_type}/{id}/files` to upload the XSLT stylesheet; the system stores the file as `text/xml`.
4. Attacker records the assigned ID of the stored XSLT file.
5. Attacker creates an XML document containing an `<?xml-stylesheet ...?>` processing instruction pointing to the URL of the previously uploaded XSLT file.
6. Attacker uploads the referencing XML document via the same API endpoint and records its ID.
7. Attacker lures an authenticated victim to visit the URL `.../files/{DATA_FILE_ID}?inline=true` within the Snipe-IT application.
8. Victim's browser loads the XML, interprets the stylesheet instruction, and executes the embedded JavaScript in the Snipe-IT session context.

## Impact

Successful exploitation allows for complete compromise of the victim's session within the Snipe-IT application. Consequences include the ability to read same-origin data (asset, user, and license information), perform authenticated state-changing actions, and potentially achieve full administrative account compromise if a superuser interacts with the malicious file.

## Recommendation

1. Upgrade Snipe-IT to version 8.7.0 or later to ensure the API controller correctly implements `StorageHelper::allowSafeInline()` for file downloads.
2. Review recent access logs for the `/api/v1/*/files/*` endpoints to identify unusual file upload patterns, particularly involving XML content.
3. Limit file upload permissions to the minimum number of users required for business operations to reduce the attack surface.
