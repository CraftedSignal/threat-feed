---
title: phpMyFAQ Unauthenticated Information Disclosure via Solution ID Enumeration
slug: 2026-05-phpmyfaq-info-disclosure
description: phpMyFAQ before 4.1.2 contains an information disclosure vulnerability in the getIdFromSolutionId() method, allowing unauthenticated attackers to enumerate restricted FAQ entries and read their titles via predictable URL patterns.
date: "2026-05-15T19:20:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - phpmyfaq
  - enumeration
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (< 4.1.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-46366
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46366
rules:
  - title: Detect phpMyFAQ Unauthenticated FAQ Enumeration
    description: Detects CVE-2026-46366 exploitation — monitors HTTP 302 redirects from /solution_id_{id}.html, indicating potential unauthenticated enumeration of restricted FAQ entries.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - webserver
  - title: Detect phpMyFAQ FAQ Title Disclosure in Redirect Location Header
    description: Detects CVE-2026-46366 exploitation — monitors HTTP 302 redirects with Location headers containing phpMyFAQ FAQ titles, potentially revealing sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.2 is vulnerable to an information disclosure flaw. Specifically, the `getIdFromSolutionId()` method lacks proper permission filtering. This vulnerability allows unauthenticated attackers to enumerate restricted FAQ entries. The attack involves exploiting predictable URL patterns such as `/solution_id_{id}.html`. By sequentially iterating through solution IDs, an attacker can discover all FAQs, even those restricted to specific users or groups. The titles of these FAQs are leaked through redirect Location headers and canonical link tags within the page source, exposing sensitive metadata without requiring any authentication. This vulnerability can significantly undermine the confidentiality of information stored within phpMyFAQ.

## Attack Chain

1. An unauthenticated attacker sends an HTTP GET request to `/solution_id_1.html`.
2. The phpMyFAQ application processes the request through the vulnerable `getIdFromSolutionId()` method.
3. If solution ID 1 exists, the server responds with an HTTP 302 redirect.
4. The `Location` header in the redirect response contains the full URL of the FAQ entry, including the title or a descriptive fragment of the title.
5. The attacker then iterates through subsequent solution IDs (e.g., `/solution_id_2.html`, `/solution_id_3.html`, etc.).
6. For each valid solution ID, the server returns an HTTP 302 redirect, leaking the FAQ title in the `Location` header.
7. The attacker records the leaked titles and associated solution IDs.
8. The attacker can now access restricted FAQ entries by directly visiting the URLs obtained through enumeration.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to enumerate and read the titles of all FAQ entries within a phpMyFAQ instance, including those restricted to specific user groups. This can lead to the disclosure of sensitive information intended only for authorized users. The number of potential victims depends on the deployment size and configuration of phpMyFAQ instances. If successfully exploited, attackers can gain unauthorized access to information that could compromise an organization's security posture, such as internal policies, procedures, or sensitive data.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.2 or later to patch CVE-2026-46366.
*   Deploy the Sigma rule `Detect phpMyFAQ Unauthenticated FAQ Enumeration` to identify potential exploitation attempts by monitoring HTTP 302 redirects from /solution_id_{id}.html.
*   Implement rate limiting on requests to `/solution_id_{id}.html` to mitigate enumeration attempts.
