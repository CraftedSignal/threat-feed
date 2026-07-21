---
title: Unauthenticated SQL Injection Vulnerability in Linknat VOS3000 and VOS2009
slug: 2026-07-linknat-sql-injection
description: An unauthenticated SQL injection vulnerability (CVE-2016-20096) exists in Linknat VOS3000 and VOS2009 through version 2.1.2.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'name' parameter in a POST request to the login endpoint, which leads to the extraction of plaintext credentials and other database content with DBA-level privileges.
date: "2026-07-21T19:21:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - Linknat
products:
  - VOS3000 <= 2.1.2.0
  - VOS2009 <= 2.1.2.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Linknat VOS3000 and VOS2009 through version 2.1.2.0 contain an unauthenticated SQL injection vulnerability that allows remote attackers to execute arbitrary SQL commands by manipulating the name parameter in a POST request to the login endpoint.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can inject malicious SQL through the login form and retrieve injected query results from a subsequent session request, enabling extraction of plaintext credentials and other database content with DBA-level privileges.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: enabling extraction of plaintext credentials and other database content with DBA-level privileges.
    confidence_band: high
cves:
  - id: CVE-2016-20096
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20096
rules:
  - title: Detects CVE-2016-20096 Exploitation - SQL Injection via Login Endpoint
    description: Detects CVE-2016-20096 exploitation - Unauthenticated SQL injection attempts in Linknat VOS3000/VOS2009 via manipulation of the 'name' parameter in a POST request to the login endpoint.
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

CVE-2016-20096 details a critical unauthenticated SQL injection vulnerability affecting Linknat VOS3000 and VOS2009 software, specifically in versions up to and including 2.1.2.0. This flaw allows remote attackers to compromise the system by injecting malicious SQL commands into the 'name' parameter during a POST request to the application's login endpoint. The vulnerability permits the execution of arbitrary SQL commands, enabling attackers to extract sensitive data, including plaintext credentials and other database content, with privileges equivalent to a Database Administrator (DBA). The exploitation does not require any prior authentication, making it a severe initial access vector. This vulnerability poses a significant risk as it can lead to full compromise of the affected VoIP billing and customer management systems, impacting data confidentiality and integrity.

## Attack Chain

1. An unauthenticated remote attacker crafts a specially designed POST request targeting the `/login` endpoint of a vulnerable Linknat VOS3000 or VOS2009 instance.
2. The attacker embeds malicious SQL injection payloads within the `name` parameter of the POST request, such as `admin' OR 1=1--` or `admin' UNION SELECT username,password FROM users--`.
3. The vulnerable application processes this request, failing to properly sanitize the input, which causes the injected SQL commands to be executed on the backend database.
4. The injected SQL commands are designed to extract sensitive information, such as plaintext user credentials, session tokens, or other valuable database content, leveraging DBA-level privileges.
5. The attacker then initiates a subsequent session request to the application to retrieve the results of the executed SQL query.
6. The application's response to the session request inadvertently includes the data extracted by the malicious SQL command.
7. The attacker successfully obtains plaintext credentials and other sensitive database information, thereby achieving unauthorized, high-privilege access to the system.

## Impact

The successful exploitation of CVE-2016-20096 grants unauthenticated remote attackers the ability to execute arbitrary SQL commands with DBA-level privileges. This directly leads to the complete extraction of sensitive database content, including plaintext user credentials. Organizations utilizing affected Linknat VOS3000 or VOS2009 versions face severe risks to data confidentiality and integrity. If exploited, attackers can gain unauthorized access to the entire system, potentially disrupt VoIP services, compromise customer data, and establish persistent access, leading to further attacks.

## Recommendation

* Immediately patch Linknat VOS3000 and VOS2009 to a version higher than 2.1.2.0 to remediate CVE-2016-20096.
* Deploy the `Detects CVE-2016-20096 Exploitation - SQL Injection via Login Endpoint` Sigma rule to your SIEM to detect attempts to exploit this vulnerability.
* Review web server access logs for POST requests to the `/login` endpoint containing suspicious characters or SQL keywords in the `name` parameter, as identified by the Sigma rule.
