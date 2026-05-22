---
title: YesWiki Unauthenticated SQL Injection Vulnerability
slug: 2026-05-yeswiki-sqli
description: YesWiki versions prior to 4.6.4 are vulnerable to an unauthenticated SQL injection in the Bazar form-import path (`FormManager::create()`), allowing an unauthenticated attacker to inject arbitrary SQL into an `INSERT` statement and read the full database, including `yeswiki_users.password` hashes (CVE-2026-46670).
date: "2026-05-22T15:40:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - web-application
  - yeswiki
vendors:
  - YesWiki
products:
  - yeswiki/yeswiki (< 4.6.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jwvv-qr7q-cv8j
  - CVE-2026-46670
rules:
  - title: Detect YesWiki Unauthenticated SQL Injection Attempt
    description: Detects CVE-2026-46670 exploitation — detects HTTP POST requests to the Bazar form import endpoint with potential SQL injection attempts in the imported-form parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect YesWiki Data Exfiltration via API
    description: Detects encoded data retrieval from /?api/forms, potentially indicating successful SQL injection and data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
rules_count: 2
---

YesWiki is susceptible to an unauthenticated SQL injection vulnerability within the Bazar form-import functionality, specifically affecting versions prior to 4.6.4. The vulnerability resides in the `FormManager::create()` function, where unsanitized input is concatenated into an SQL INSERT statement. This allows any unauthenticated visitor to inject arbitrary SQL code and potentially extract sensitive information, including user credentials, from the database. The issue was identified and analyzed against commit `1f485c049db030b94c047ec219e63534ac81142e`. Exploitation is straightforward, requiring only a crafted HTTP POST request, making this a critical vulnerability for any publicly accessible YesWiki instance.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP POST request to the `/?BazaR&vue=formulaire` endpoint.
2. The request contains a specially crafted `imported-form` parameter with SQL injection payload.
3. The `FormManager::create()` function (FormManager.php#L258) processes the request and concatenates the malicious input into an SQL INSERT statement without proper sanitization.
4. The injected SQL code executes within the context of the YesWiki database.
5. The attacker uses the SQL injection to extract data from the `yeswiki_users` table, including email addresses and password hashes.
6. The extracted data is encoded and embedded within the `bn_id_nature` field of a newly created database entry.
7. The attacker then sends a request to `/?api/forms` to retrieve the `bn_id_nature` field.
8. The attacker decodes the extracted data to obtain sensitive information, such as usernames, emails, and password hashes.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46670) allows an unauthenticated attacker to dump the entire YesWiki database. This includes sensitive information such as usernames, email addresses, and, most critically, hashed passwords of all users. This complete data breach can lead to account compromise, unauthorized access to sensitive wiki content, and potential lateral movement within the organization if users reuse passwords across multiple services. The impact is particularly severe given the ease of exploitation.

## Recommendation

*   Upgrade YesWiki to version 4.6.4 or later to patch the SQL injection vulnerability in `FormManager::create()` (reference: GHSA-jwvv-qr7q-cv8j).
*   Deploy the Sigma rule "Detect YesWiki Unauthenticated SQL Injection Attempt" to detect exploitation attempts against the vulnerable endpoint.
*   Monitor web server logs for POST requests to `/?BazaR&vue=formulaire` with suspicious characters in the `imported-form` parameter (reference: sample HTTP request in the content).
*   Apply the Sigma rule "Detect YesWiki Data Exfiltration via API" to detect attempts to retrieve encoded data using the `/?api/forms` endpoint after successful SQL injection.
