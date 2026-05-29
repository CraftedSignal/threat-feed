---
title: Apache CouchDB Improper Privilege Management Leads to Remote Code Execution
slug: 2026-05-couchdb-privesc-rce
description: A public exploit demonstrates improper privilege management in Apache CouchDB (CVE-2017-12635) leading to privilege escalation, which can be combined with CVE-2017-12636 for remote code execution by modifying server configurations via the HTTP API.
date: "2026-05-29T20:02:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:couchdb:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:couchdb:2.0.0:rc1:*:*:*:*:*:*
  - cpe:2.3:a:apache:couchdb:2.0.0:rc2:*:*:*:*:*:*
  - cpe:2.3:a:apache:couchdb:2.0.0:rc3:*:*:*:*:*:*
  - cpe:2.3:a:apache:couchdb:2.0.0:rc4:*:*:*:*:*:*
tags:
  - privilege-escalation
  - remote-code-execution
  - couchdb
  - CVE-2017-12635
  - CVE-2017-12636
vendors:
  - Apache
products:
  - CouchDB 1.6.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569.002
    technique_name: 'System Services: Service Execution'
cves:
  - id: CVE-2017-12635
    cvss: 9.8
    epss: 0.94098
  - id: CVE-2017-12636
    cvss: 7.2
    epss: 0.93752
references:
  - https://sploitus.com/exploit?id=91E99754-E8D0-5B4C-A0EC-525AF2DFC914&utm_source=rss&utm_medium=rss
  - CVE-2017-12635
  - CVE-2017-12636
rules:
  - title: Detect CVE-2017-12635 Exploitation Attempt - Duplicate Roles in User Creation
    description: Detects attempts to exploit CVE-2017-12635 by creating a user with duplicate 'roles' keys in the JSON payload, indicating potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - cve-2017-12635
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2017-12636 Exploitation Attempt - Modifying CouchDB Query Servers Configuration
    description: Detects attempts to exploit CVE-2017-12636 by modifying the CouchDB query_servers configuration, potentially leading to remote code execution.
    platform: sigma
    severity: high
    tactics:
      - cve-2017-12636
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
rules_count: 2
---

A public exploit has surfaced detailing a critical vulnerability in Apache CouchDB version 1.6.0. This exploit leverages CVE-2017-12635, an improper privilege management flaw, enabling an attacker to gain administrative privileges. By exploiting inconsistent handling of duplicate JSON `roles` keys, a malicious actor can create a new user with administrator rights. This privilege escalation serves as a stepping stone to CVE-2017-12636, which allows remote code execution by modifying CouchDB's configuration via the HTTP API. The vulnerability is triggered when CouchDB versions prior to 1.7.1 process design functions that declare a "language" field. Successful exploitation can lead to complete system compromise as the attacker gains the ability to execute arbitrary commands on the server.

## Attack Chain

1.  The attacker probes the target CouchDB instance, identifying version 1.6.0 running on port 5984.
2.  The attacker exploits CVE-2017-12635 by sending a crafted HTTP PUT request to the `/_users` endpoint with a JSON payload containing duplicate "roles" keys. The first "roles" key grants admin privileges, while the second bypasses validation.
3.  A new user account, such as "hacker", is created with administrative privileges due to the vulnerability in JSON parsing.
4.  The attacker authenticates to the CouchDB instance using the newly created admin account.
5.  The attacker exploits CVE-2017-12636 by sending an HTTP PUT request to the `/_config/query_servers/cmd` endpoint, setting the value to an OS command (e.g., "id 1>/tmp/pwned 2>&1").
6.  The attacker creates a new database (e.g., "rcetest") and a design document with a view using the "cmd" language.
7.  The attacker triggers the view by sending an HTTP GET request to the `/rcetest/_design/rce/_view/myview` endpoint.
8.  CouchDB executes the configured OS command under the privileges of the CouchDB process (couchdb user), achieving remote code execution.

## Impact

Successful exploitation allows attackers to gain full control of the CouchDB instance. This includes the ability to read, modify, and delete sensitive data stored within the databases. Furthermore, by leveraging remote code execution (CVE-2017-12636), attackers can execute arbitrary commands on the server with the privileges of the CouchDB process. While the exploit described in the source material shows code execution with the privileges of the "couchdb" user (uid=1000), it remains sufficient to achieve Remote Code Execution within the boundaries of the service permissions and further compromise the host system.

## Recommendation

*   Immediately upgrade Apache CouchDB to a secure version (≥ 1.7.1 or ≥ 2.1.1, recommended version 3.x) to patch CVE-2017-12635 and CVE-2017-12636.
*   Configure `require_valid_user = true` in the `local.ini` configuration file to block all anonymous API access, mitigating CVE-2017-12635.
*   Implement network segmentation to restrict access to port 5984 (CouchDB HTTP API) to only trusted IPs.
*   Use `config_whitelist` in the `local.ini` file to restrict which configuration keys can be modified via the API, preventing attackers from leveraging the `/_config/query_servers` endpoint to inject OS commands, addressing CVE-2017-12636.
