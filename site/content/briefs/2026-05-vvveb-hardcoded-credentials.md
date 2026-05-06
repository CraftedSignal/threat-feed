---
title: Vvveb Hardcoded Credentials Vulnerability in phpMyAdmin Container
slug: 2026-05-vvveb-hardcoded-credentials
description: Vvveb versions before 1.0.8.2 contain a hardcoded credentials vulnerability in the docker-compose-apache.yaml configuration, allowing unauthenticated attackers to access the phpMyAdmin container and gain unrestricted read and write access to the Vvveb database, leading to account takeover and data manipulation.
date: "2026-05-06T19:16:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - hardcoded-credentials
  - phpmyadmin
  - docker
  - vulnerability
vendors:
  - Vvveb
products:
  - Vvveb
  - phpMyAdmin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-41930
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41930
rules:
  - title: Detect Access to phpMyAdmin Login Page
    description: Detects HTTP requests to the phpMyAdmin login page, which could indicate an attempted exploit of the hardcoded credentials vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect phpMyAdmin access from unusual source IP
    description: Detects connections to phpMyAdmin from IP addresses not typically associated with database administration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Vvveb, a web page builder, versions before 1.0.8.2 are susceptible to a critical vulnerability stemming from hardcoded credentials within the `docker-compose-apache.yaml` file. This misconfiguration exposes the bundled phpMyAdmin container, providing unauthenticated attackers with a readily available pathway to compromise the entire Vvveb database. By exploiting these default credentials, attackers circumvent normal authentication procedures and gain complete control over sensitive data. This includes administrator password hashes, customer Personally Identifiable Information (PII), and order details. The ease of exploitation and the potential for significant data breach make this vulnerability a critical risk for any organization using affected versions of Vvveb.

## Attack Chain

1.  Attacker identifies a Vvveb instance running a version prior to 1.0.8.2.
2.  Attacker accesses the phpMyAdmin service exposed by the vulnerable Vvveb instance, typically on port 80 or 443 depending on the configuration.
3.  Attacker uses the hardcoded credentials found in the `docker-compose-apache.yaml` file to authenticate to the phpMyAdmin interface without needing to bypass any security measures.
4.  Upon successful authentication, the attacker gains unrestricted read and write access to the entire Vvveb database through the phpMyAdmin interface.
5.  Attacker extracts sensitive information, including administrator password hashes, customer PII, and order data.
6.  Attacker uses the compromised administrator password hashes to gain administrative access to the Vvveb application.
7.  Attacker manipulates database records to modify user accounts, alter orders, or inject malicious code into the website.
8.  Attacker achieves full account takeover and data manipulation capabilities, potentially leading to significant financial loss and reputational damage.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to compromise the entire Vvveb database. This grants access to sensitive customer data, including PII and financial information, as well as administrator credentials. Consequences include account takeover, data theft, and manipulation of website content. Given the widespread use of phpMyAdmin and the ease of exploitation, organizations running vulnerable versions of Vvveb are at significant risk of data breaches and financial losses. The CVSS v3.1 base score of 9.8 highlights the critical nature of this vulnerability.

## Recommendation

*   Upgrade Vvveb to version 1.0.8.2 or later to patch CVE-2026-41930.
*   If upgrading is not immediately feasible, restrict access to the phpMyAdmin container by modifying firewall rules to only allow access from trusted IP addresses or internal networks.
*   Deploy the Sigma rule to detect unauthorized access attempts to the phpMyAdmin interface via specific HTTP requests targeting phpMyAdmin login pages.
