---
title: Joomla com_booking Information Disclosure (CVE-2023-54357)
slug: 2026-06-joomla-booking-info-disclosure
description: An unauthenticated information disclosure vulnerability (CVE-2023-54357) in the Joomla com_booking component version 2.4.9 allows attackers to enumerate user accounts, including names, usernames, and email addresses, by exploiting the getUserData function via specific GET requests.
date: "2026-06-19T19:23:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - joomla
  - web-vulnerability
  - information-disclosure
  - cve
vendors:
  - Artio
  - Joomla
products:
  - Joomla! com_booking component 2.4.9
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54357
  - http://www.artio.net/
  - http://www.artio.net/downloads/joomla/book-it/book-it-2-free/download
  - https://www.exploit-db.com/exploits/51595
  - https://www.vulncheck.com/advisories/joomla-com-booking-information-disclosure-via-account-enumeration
rules:
  - title: Detect Joomla com_booking Information Disclosure (CVE-2023-54357)
    description: Detects CVE-2023-54357 exploitation — HTTP GET requests attempting to enumerate user accounts via the com_booking component's getUserData function.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1589
      - T1589.002
      - T1592
      - T1592.002
    data_sources:
      - webserver
rules_count: 1
---

CVE-2023-54357 is an information disclosure vulnerability affecting version 2.4.9 of the Joomla com_booking component. Unauthenticated attackers can exploit this flaw to enumerate sensitive user account information, including names, usernames, and email addresses. The vulnerability resides within the `getUserData` function of the `customer` controller, allowing an attacker to send specially crafted HTTP GET requests to `index.php` with specific parameters (`option=com_booking`, `controller=customer`, `task=getUserData`, and an `id`). By brute-forcing the `id` parameter, an adversary can systematically collect a list of valid user accounts on the affected Joomla instance. This exposure of user data can facilitate further attacks such as credential stuffing, phishing, or targeted social engineering, making it a significant concern for organizations using the vulnerable component.

## Attack Chain

1.  **Reconnaissance**: An unauthenticated attacker identifies a Joomla web application running the vulnerable `com_booking` component, version 2.4.9.
2.  **Vulnerability Probing**: The attacker constructs an HTTP GET request targeting the `index.php` endpoint of the Joomla application.
3.  **Parameter Injection**: The GET request includes the parameters `option=com_booking`, `controller=customer`, `task=getUserData`, and an `id` parameter (e.g., `id=1`).
4.  **Information Retrieval**: The vulnerable `getUserData` function processes the request and, for valid `id` values, returns JSON or XML data containing the corresponding user's name, username, and email address.
5.  **Brute-Force Enumeration**: The attacker repeatedly sends GET requests, systematically incrementing or varying the `id` parameter to enumerate multiple user accounts present on the system.
6.  **Data Collection**: The attacker collects the exposed user data, including names, usernames, and email addresses, for all successfully enumerated accounts.
7.  **Subsequent Attack Preparation**: The collected information is then used as a basis for further malicious activities, such as credential stuffing attacks against other services, targeted phishing campaigns, or social engineering schemes.

## Impact

The primary impact of CVE-2023-54357 is the unauthorized disclosure of sensitive user information. If exploited, an attacker gains access to a list of registered user names, their associated usernames, and email addresses. This data can be leveraged for various follow-on attacks, including credential stuffing against other services if users reuse passwords, highly effective spear-phishing campaigns tailored to the enumerated individuals, or general social engineering attacks. While the vulnerability itself does not grant direct access to the system or modify data, the leaked information significantly lowers the bar for attackers to compromise user accounts or target individuals within the organization, leading to potential data breaches, financial loss, or reputational damage.

## Recommendation

*   **Patch CVE-2023-54357**: Immediately upgrade the Joomla `com_booking` component to a version higher than 2.4.9 to remediate CVE-2023-54357.
*   **Deploy Sigma Rule**: Deploy the `Detect Joomla com_booking Information Disclosure (CVE-2023-54357)` Sigma rule provided in this brief to your SIEM for real-time detection of exploitation attempts.
*   **Monitor Web Server Logs**: Configure and actively monitor web server access logs for unusual patterns involving GET requests to `index.php` with `option=com_booking`, `controller=customer`, `task=getUserData`, and an `id` parameter.
