---
title: 'CVE-2017-20257: Joomla! Component Quiz Deluxe SQL Injection'
slug: 2026-06-joomla-quiz-deluxe-sql-injection
description: An unauthenticated SQL injection vulnerability (CVE-2017-20257) in Joomla! Component Quiz Deluxe 3.7.4 allows attackers to execute arbitrary SQL commands and extract sensitive information via the `ajaxaction.flag_question` task using `stu_quiz_id` or `flag_quest` parameters.
date: "2026-06-19T16:26:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - joomla
  - cve
  - data-exfiltration
vendors:
  - Joomplace
products:
  - Quiz Deluxe 3.7.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
cves:
  - id: CVE-2017-20257
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20257
  - https://www.exploit-db.com/exploits/42589
  - https://www.vulncheck.com/advisories/joomla-component-quiz-deluxe-sql-injection
rules:
  - title: Detects CVE-2017-20257 Exploitation - SQLi in Quiz Deluxe Flag Question Task (Basic)
    description: Detects CVE-2017-20257 exploitation – unauthenticated SQL injection attempts targeting the `ajaxaction.flag_question` task with common SQL injection delimiters in `stu_quiz_id` or `flag_quest` parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1059.008
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2017-20257 Exploitation - SQLi Keywords in Quiz Deluxe
    description: Detects CVE-2017-20257 exploitation – unauthenticated SQL injection attempts targeting the `ajaxaction.flag_question` task using common SQL keywords like UNION, SELECT, or SLEEP in `stu_quiz_id` or `flag_quest` parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1059.008
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2017-20257 describes an unauthenticated SQL injection vulnerability affecting the Joomla! Component Quiz Deluxe version 3.7.4. This critical flaw allows remote attackers to execute arbitrary SQL commands against the backend database. Attackers achieve this by injecting malicious SQL code into specific parameters (`stu_quiz_id` or `flag_quest`) when making requests to the `ajaxaction.flag_question` task within the component. The vulnerability's re-publication or update in the NVD on 2026-06-19 highlights its continued relevance. Successful exploitation could lead to full database compromise, including sensitive data exfiltration, data manipulation, and potentially further compromise of the web application.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing Joomla! instance running the vulnerable Quiz Deluxe component version 3.7.4.
2. The attacker crafts a specially designed HTTP GET or POST request targeting the `/index.php` endpoint with the `option=com_quizdeluxe&task=ajaxaction.flag_question` parameters.
3. Malicious SQL payloads, such as `' OR 1=1--` or `UNION SELECT ...`, are injected into either the `stu_quiz_id` or `flag_quest` parameters within the HTTP request.
4. The vulnerable Quiz Deluxe component processes the request without proper input sanitization, leading to the execution of the embedded SQL commands on the backend database.
5. The attacker observes the web server's response for error messages, altered content, or retrieved data, confirming successful injection.
6. Through iterative exploitation, the attacker manipulates database queries to extract sensitive information, such as user credentials, personal identifiable information (PII), or internal application data.
7. The attacker may also use the SQL injection to modify database records, potentially leading to website defacement, privilege escalation, or further compromise of the web application.

## Impact

Successful exploitation of CVE-2017-20257 grants unauthenticated attackers the ability to execute arbitrary SQL commands, severely compromising the integrity and confidentiality of the application's database. This directly leads to the exfiltration of sensitive information, including user credentials, proprietary business data, or personally identifiable information (PII) of customers. Attackers can also manipulate existing data, causing data integrity issues or unauthorized content changes on the Joomla! site. Organizations utilizing the affected component version face significant risks of severe data breaches, reputational damage, and potential regulatory compliance violations.

## Recommendation

* Immediately patch or upgrade the Joomla! Component Quiz Deluxe to a version greater than 3.7.4 to remediate CVE-2017-20257.
* Deploy the Sigma rules in this brief to your web application firewall (WAF) or SIEM to detect exploitation attempts targeting `ajaxaction.flag_question`.
* Ensure web server logging (e.g., Apache access logs, Nginx access logs, IIS logs) captures full HTTP request details including URL paths and query parameters to enable detection of SQL injection attempts.
* Implement robust input validation and parameterized queries in all web applications to prevent similar SQL injection vulnerabilities.
