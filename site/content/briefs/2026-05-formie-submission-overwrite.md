---
title: Formie Unauthenticated Submission Editing Vulnerability (CVE-2026-47266)
slug: 2026-05-formie-submission-overwrite
description: An unauthenticated user can modify existing Formie submissions by posting a known or guessed submission ID to `formie/submissions/save-submission`, affecting versions prior to 2.2.21 and versions 3.0.0 to 3.1.26.
date: "2026-05-29T22:21:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - unauthenticated-access
  - data-manipulation
  - cve
  - cloud
vendors:
  - Verbb
products:
  - Formie (< 2.2.21)
  - Formie (>= 3.0.0, < 3.1.26)
cves:
  - id: CVE-2026-47266
references:
  - https://github.com/advisories/GHSA-pgxq-p76c-x9cg
  - https://github.com/verbb/formie/releases/tag/2.2.21
  - https://github.com/verbb/formie/releases/tag/3.1.26
  - CVE-2026-47266
iocs:
  - type: email
    value: security@arcade.ch
ioc_counts:
  email: 1
rules:
  - title: Detect CVE-2026-47266 Exploitation Attempt - Formie Submission Overwrite
    description: Detects CVE-2026-47266 exploitation attempt — HTTP POST request to the `formie/submissions/save-submission` endpoint without authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A vulnerability exists in the Formie plugin that allows unauthenticated users to modify existing form submissions. By sending a crafted POST request to the `formie/submissions/save-submission` endpoint with a known or guessed submission ID, an attacker can overwrite existing submission data. This issue affects Formie versions prior to 2.2.21 and versions 3.0.0 through 3.1.26. Successful exploitation of this vulnerability could lead to data manipulation, unauthorized access to sensitive information, or other malicious activities. This vulnerability is identified as CVE-2026-47266.

## Attack Chain

1. An unauthenticated attacker identifies a target Formie installation.
2. The attacker enumerates or guesses existing submission IDs.
3. The attacker crafts a malicious POST request to `formie/submissions/save-submission`.
4. The POST request includes the targeted submission ID.
5. The POST request contains modified form field data intended to overwrite the original submission.
6. The Formie plugin processes the request without proper authentication checks.
7. The targeted submission is updated with the attacker's modified data.
8. The attacker verifies the submission has been successfully overwritten.

## Impact

Successful exploitation of CVE-2026-47266 allows unauthenticated users to modify existing Formie submissions. This could lead to data corruption, exposure of sensitive information contained within the forms, or manipulation of business processes that rely on the integrity of the submitted data. The number of affected installations is currently unknown, but any Formie instance running a vulnerable version is susceptible to this attack.

## Recommendation

*   Upgrade Formie to version 2.2.21 or 3.1.26 or later to patch CVE-2026-47266, as per the vendor's advisory.
*   As a workaround, block unauthenticated access to the `actions/formie/submissions/save-submission` endpoint, as described in the vendor's advisory.
*   Deploy the Sigma rule provided below to detect attempts to exploit this vulnerability by monitoring POST requests to the `formie/submissions/save-submission` endpoint.
