---
title: Information Exposure in phpMyFAQ Password Reset Mechanism
slug: 2026-08-phpmyfaq-token-exposure
description: Versions of phpMyFAQ prior to 4.1.7 store password reset tokens in a publicly accessible file when user tracking is enabled, allowing unauthenticated attackers to hijack accounts.
date: "2026-08-19T14:33:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - thorsten
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Unauthenticated attackers can read the tracking file at content/core/data/trackingDDMMYYYY to extract reset tokens.
    confidence_band: high
cves:
  - id: CVE-2026-75918
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75918
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-j5w2-cwwj-xj7x
rules:
  - title: Detect Unauthorized Access to phpMyFAQ Tracking Files
    description: Detects potential exploitation of CVE-2026-75918 by identifying unauthenticated attempts to access password reset tokens stored in the tracking directory.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch phpMyFAQ to version 4.1.7 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory states 4.1.7 remediates the issue
  hunt_leads:
    - lead: Search logs for access to /content/core/data/tracking files
      technique_id: T1552.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated file retrieval
  mitigation_plan:
    - priority: immediate
      action: Disable user tracking in phpMyFAQ
      owner: IT Operations
      addresses: CVE-2026-75918
      evidence: Tracking file generation is the source of the exposure
---

phpMyFAQ versions prior to 4.1.7 contain a security vulnerability (CVE-2026-75918) that results in the exposure of sensitive authentication data. When the user tracking feature is enabled within the application, the system logs password reset tokens into a tracking file stored at a predictable and publicly accessible location: content/core/data/trackingDDMMYYYY. This flaw allows an unauthenticated, remote attacker to download these files, extract valid reset tokens, and subsequently replay them against the application's password reset API. Successful exploitation permits the attacker to bypass authentication and take full control over targeted user accounts. The vulnerability is highly critical due to the ease of access to the token files and the lack of authentication required to perform the initial information gathering.

## Impact

Successful exploitation leads to a complete account takeover of any user who initiates a password reset while the tracking feature is active. This can affect all users of an impacted phpMyFAQ instance, including administrative accounts. In environments where phpMyFAQ is used for enterprise knowledge management, this could lead to significant unauthorized access to sensitive internal documentation and credentials stored within the system.

## Recommendation

Prioritize the immediate update of all phpMyFAQ instances to version 4.1.7 or later to remediate CVE-2026-75918. In the interim, detection engineering teams should implement monitoring for unauthorized access to the tracking file path.

- Deploy the provided Sigma rule to detect requests targeting the tracking file.
- Audit existing web server access logs for any GET requests matching the path pattern 'content/core/data/tracking*' to identify potential past exploitation attempts.
- Disable the user tracking feature in phpMyFAQ configuration until the software can be patched to prevent further token leakage.
