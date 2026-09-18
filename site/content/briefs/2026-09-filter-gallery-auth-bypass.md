---
title: Authorization Bypass in WordPress Filter Gallery Plugin
slug: 2026-09-filter-gallery-auth-bypass
description: The Filter Gallery WordPress plugin contains an authorization bypass vulnerability (CVE-2026-89413) allowing authenticated users with low-level privileges to delete arbitrary gallery records by omitting mandatory nonce checks.
date: "2026-09-18T08:04:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:filter_gallery:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - Filter Gallery (<= 1.1.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for authenticated attackers... to delete any arbitrary Filter Gallery records
    confidence_band: high
cves:
  - id: CVE-2026-89413
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89413
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all WordPress sites running the Filter Gallery plugin to identify affected versions <= 1.1.4
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-89413 affects all versions up to 1.1.4
  enrichment_needed:
    - item: Fixed version for Filter Gallery
      owner: CTI
      reason: Necessary to verify patching status
      evidence: NVD entry lists 1.1.4 as the last affected version
  mitigation_plan:
    - priority: immediate
      action: Disable the Filter Gallery plugin if a patch is not yet available and the risk of data destruction is high
      owner: IT Operations
      addresses: CVE-2026-89413
      evidence: Source confirms authorization bypass vulnerability in 1.1.4
---

The Filter Gallery plugin for WordPress is affected by an authorization bypass vulnerability, tracked as CVE-2026-89413, impacting all versions up to and including 1.1.4. The flaw originates from the plugin's failure to enforce adequate authorization checks when performing administrative actions. Consequently, any authenticated user with at least subscriber-level permissions can trigger the deletion of arbitrary gallery records, including associated image mappings, configurations, and metadata. 

The vulnerability is specifically characterized by an improper nonce validation mechanism. Attackers can bypass this security control by omitting the nonce field entirely in the HTTP POST request; the plugin incorrectly processes the request as valid when the field is absent, whereas it properly rejects requests containing an incorrect or malformed nonce. This vulnerability allows for unauthorized data destruction within the WordPress environment, potentially impacting site functionality and content management workflows.

## Attack Chain

1. Attacker obtains a valid WordPress user account with at least subscriber-level privileges via self-registration or compromised credentials.
2. Attacker logs into the WordPress administrative interface or interacts directly with the site's REST API/admin-ajax endpoints.
3. Attacker identifies the specific target gallery IDs by enumerating accessible gallery resources or guessing integer sequences.
4. Attacker constructs a malicious HTTP POST request targeting the Filter Gallery deletion endpoint.
5. Attacker explicitly omits the expected 'nonce' parameter from the POST body to bypass the plugin's security verification.
6. The web server passes the request to the vulnerable plugin, which fails to validate the user's authorization and the presence of the nonce.
7. The plugin executes the deletion operation for the specified gallery record within the WordPress database.
8. The targeted gallery, including its associated filters and image mappings, is permanently removed.

## Impact

Successful exploitation allows low-privileged attackers to perform unauthorized destructive actions against gallery data. Victims face the loss of all image mappings, custom settings, and filter configurations associated with the targeted galleries, requiring manual restoration from backups. This vulnerability affects any WordPress site running Filter Gallery version 1.1.4 or earlier.

## Recommendation

Prioritized actions for security operations and IT teams:
- Identify and audit all WordPress installations currently utilizing the 'Filter Gallery' plugin.
- Patch the plugin to the version that remediates CVE-2026-89413 immediately upon availability.
- Review web server access logs for anomalous POST requests directed at plugin-specific administrative endpoints lacking standard security tokens.
- Monitor for unauthorized user activity originating from subscriber-level accounts that perform bulk deletion of content or database records.
