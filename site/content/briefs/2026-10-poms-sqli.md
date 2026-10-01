---
title: SQL Injection Vulnerability in Purchase Order Management System (POMS)
slug: 2026-10-poms-sqli
description: Purchase Order Management System (POMS) version 1.0 is vulnerable to unauthenticated SQL injection via the password parameter, allowing for exfiltration or out-of-band communication via the MySQL load_file function.
date: "2026-10-01T14:11:59Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - nu11secur1ty
vendors:
  - oretnom23
products:
  - Purchase Order Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The password parameter appears to be vulnerable to SQL injection attacks.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52684
  - https://www.sourcecodester.com/php/14935/purchase-order-management-system-using-php-free-source-code.html
iocs:
  - type: domain
    value: y10in4ofvosyskgb5c9a7e55mwssgkf86bu3hu5j.oastify.com
ioc_counts:
  domain: 1
rules:
  - title: Detect POMS Login SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the POMS login endpoint by looking for suspicious SQL functions like load_file in POST requests.
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
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to inspect POST requests to /purchase_order/classes/Login.php for SQL injection keywords.
      owner: SOC
      due: 24h
      evidence: Source identified SQLi in password field of Login.php
  hunt_leads:
    - lead: Search web logs for POST requests containing 'load_file' or SQL comment characters in the request body.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit-DB PoC uses load_file payload.
  mitigation_plan:
    - priority: immediate
      action: Sanitize and parameterize all input fields on POMS login forms.
      owner: IT Operations
      addresses: SQL Injection vulnerability in Login.php
      evidence: Vulnerability class SQLi identified.
---

Purchase Order Management System (POMS) version 1.0 is affected by a critical SQL injection vulnerability in its login authentication logic. The vulnerability exists within the 'password' parameter processed by '/purchase_order/classes/Login.php'. An attacker can send a crafted POST request to this endpoint to execute arbitrary SQL sub-queries. The proof-of-concept demonstrates the use of the MySQL 'load_file' function to perform an out-of-band (OOB) DNS lookup, which confirms that the application can be forced to interact with attacker-controlled external infrastructure. This vulnerability poses a significant risk to the integrity and confidentiality of the database connected to the application, as successful exploitation could lead to credential harvesting or database dumping.

## Attack Chain

1. The attacker identifies the login endpoint at '/purchase_order/admin/login.php'.
2. The attacker crafts an HTTP POST request targeting '/purchase_order/classes/Login.php?f=login'.
3. The attacker injects a malicious SQL string into the 'password' field.
4. The payload utilizes the 'load_file' function to reference a UNC path, forcing a DNS request to an external domain.
5. The application backend processes the request and executes the injected SQL command.
6. The external OAST server (e.g., OASTify) receives the DNS query, confirming successful injection.
7. The attacker proceeds to extract sensitive information or bypass authentication mechanisms.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to interact with the underlying MySQL database. This can lead to unauthorized access to system credentials, the theft of sensitive procurement data, or potential further compromise of the web application environment.

## Recommendation

1. Implement input sanitization and parameterization for all user-supplied data in 'classes/Login.php', specifically for the 'username' and 'password' parameters.
2. Deploy the provided Sigma rule to detect malicious SQL injection patterns in web server logs.
3. Block outbound DNS requests from the web application server to untrusted or non-whitelisted domains to prevent OOB exfiltration.
4. Audit logs for anomalous activity targeting the '/purchase_order/classes/Login.php' endpoint.
