---
title: Unauthenticated Access Control Bypass in JoomGallery
slug: 2026-08-joomgallery-bypass
description: JoomGallery versions 4.3.0 and earlier are vulnerable to an access control bypass via the JSON view component, allowing unauthenticated attackers to retrieve protected image metadata and bypass password gates to download private content.
date: "2026-08-23T16:57:04Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - JoomGallery
products:
  - JoomGallery (<= 4.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated access control bypass exists in JoomGallery's category JSON view.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The attacker can retrieve the category's title, description, and the randomized filenames of all protected images.
    confidence_band: high
cves:
  - id: CVE-2026-66916
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66916
  - https://github.com/advisories/GHSA-g79m-pfhw-2c5m
  - https://www.joomgalleryfriends.net/en/blog/joomgallery-4-en/joomgallery-4-4-0.html
rules:
  - title: Detect CVE-2026-66916 Exploitation Attempt
    description: Detects unauthenticated requests to the JoomGallery JSON category view, a potential indicator of CVE-2026-66916 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch JoomGallery to version 4.4.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-66916 fix in 4.4.0
    - action: Deploy Sigma detection for format=json queries
      owner: Detection Engineering
      due: 48h
      evidence: Exploit path identified in JsonView.php
---

JoomGallery versions 4.3.0 and earlier suffer from an improper access control vulnerability (CVE-2026-66916) in the `JsonView.php` component. While the HTML-based view correctly enforces password protection for gallery categories, the JSON interface (`format=json`) fails to implement the required `pw_protected` flag checks. This oversight permits unauthenticated remote attackers to query any public-access category ID and receive a full JSON object containing category titles, descriptions, and randomized file paths for protected images. Because JoomGallery relies on the obscurity of these randomized filenames for its security model, the leakage of filenames allows attackers to download the underlying protected images directly from the web server's static directory. This vulnerability affects JoomGallery installations running on Joomla, as the framework does not propagate access checks across different view formats.

## Attack Chain

1. Attacker identifies a JoomGallery installation and identifies target category IDs, which are sequential and easily enumerated.
2. Attacker crafts an HTTP GET request to the target component: `index.php?option=com_joomgallery&view=category&format=json&id=[ID]`.
3. The web server routes the request to `site/com_joomgallery/src/View/Category/JsonView.php`.
4. The application logic executes `getImages()` without verifying if the requested category is password protected.
5. The application serializes the category's private data, including randomized full filenames, into a JSON response.
6. The attacker receives the JSON response containing the secret image filenames.
7. The attacker constructs a direct request to the static file path: `/images/joomgallery/originals/[filename]`.
8. The web server serves the protected image directly, completing the unauthorized access.

## Impact

Successful exploitation allows for the full disclosure of private gallery metadata and the unauthorized download of password-protected images. Since categories are enumerable via ID, an attacker can systematically harvest all content from any password-protected, public-access category. This vulnerability impacts all users of JoomGallery versions 4.3.0 and earlier until upgraded to 4.4.0.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Upgrade JoomGallery to version 4.4.0 immediately to address CVE-2026-66916.
- Implement web server access controls or WAF rules to block access to the `/images/joomgallery/originals/` directory from external requests.
- Deploy the Sigma rules below to detect attempts to access the vulnerable JSON view endpoint.
- Audit existing JoomGallery categories to ensure sensitive images are not stored in directories exposed via direct web requests.
