---
title: SQL Injection in phpMyFAQ StopWords::add()
slug: 2026-09-phpmyfaq-sqli
description: An authenticated administrator can exploit an unescaped SQL insertion vulnerability in the phpMyFAQ StopWords::add() method (CVE-2026-56738) to execute arbitrary database commands.
date: "2026-09-24T20:05:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phpmyfaq:phpmyfaq:*:*:*:*:*:*:*:*
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (<= 4.1.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated administrator who can reach the stop-word management feature can submit a crafted value as the word parameter that breaks out of the SQL string literal and injects arbitrary SQL.
    confidence_band: high
cves:
  - id: CVE-2026-56738
references:
  - https://github.com/advisories/GHSA-rw77-vq4g-x3hp
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade phpMyFAQ to a version higher than 4.1.5
      owner: IT Operations
      due: 48h
      evidence: Source states affected versions are <= 4.1.5
  mitigation_plan:
    - priority: immediate
      action: Implement input validation on the stop-word administrative form to block suspicious SQL characters
      owner: Development
      addresses: CVE-2026-56738
      evidence: The omission is isolated to the add() code path
---

phpMyFAQ versions up to and including 4.1.5 contain a SQL injection vulnerability within the `StopWords::add()` method in `src/phpMyFAQ/StopWords.php`. The vulnerability occurs because the application uses `sprintf()` to construct SQL queries but fails to sanitize the user-supplied stop word input using the database driver's `escape()` method. While sibling methods like `StopWords::update()` correctly implement escaping, the `add()` method omits this security control, creating an inconsistency that allows authenticated administrative users to break out of the SQL string literal. 

An attacker with administrative privileges can inject arbitrary SQL commands, such as `DROP TABLE`, `UNION`-based exfiltration, or unauthorized data modification. While the threat requires authenticated administrative access, it represents a significant risk for environments where administrative sessions may be hijacked or compromised, or where administrative credentials are shared.

## Attack Chain

1. Attacker gains access to a valid phpMyFAQ administrator session through credential theft or session hijacking.
2. Attacker logs into the phpMyFAQ administration panel.
3. Attacker navigates to the Stop Words management interface.
4. Attacker enters a malicious payload containing SQL metacharacters (e.g., `test', 'en'); DROP TABLE faqstopwords; --`) into the new stop word field.
5. The `StopWords::add()` method processes the unsanitized input via `sprintf()` and constructs a malformed SQL query.
6. The application executes the concatenated SQL statement against the backend database.
7. The database driver interprets the injected content as a legitimate second command, leading to unauthorized data exfiltration or table destruction.

## Impact

Successful exploitation allows an authenticated administrator to bypass intended application logic to perform unauthorized database operations. This can lead to total loss of database integrity through table deletion, exfiltration of sensitive FAQ content or user credentials, and modification of internal application data. The vulnerability highlights a failure in input validation that persists until the application is patched to use consistent escaping or, preferably, prepared statements.

## Recommendation

1. Upgrade phpMyFAQ to a version later than 4.1.5 immediately to resolve the inconsistency in the `StopWords::add()` method.
2. Audit database query patterns across the `StopWords` class to ensure consistent use of `escape()` for all input parameters concatenated into SQL strings.
3. Prioritize migrating `sprintf()`-based database interactions to parameterized or prepared statements (e.g., `PDO::prepare()`) to structurally eliminate this class of vulnerability.
4. Monitor web server logs for administrative accounts performing suspicious SQL syntax patterns (e.g., `UNION`, `DROP TABLE`) originating from the stop words management endpoints.
