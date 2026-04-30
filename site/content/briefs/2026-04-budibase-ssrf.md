---
title: Budibase REST Connector SSRF via Empty Blacklist
slug: 2026-04-budibase-ssrf
description: A critical Server-Side Request Forgery (SSRF) vulnerability in Budibase's REST datasource connector allows attackers with Builder privileges to exfiltrate sensitive data from internal network services due to a missing default IP blacklist.
date: "2026-04-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - budibase
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Remote Services Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: 'Remote Services: RDP'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.001
    technique_name: 'Email Collection: Local Email Collection'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://github.com/advisories/GHSA-7r9j-r86q-7g45
rules:
  - title: Detect Budibase REST Datasource Creation Targeting Internal IPs
    description: Detects the creation of Budibase REST datasources that target internal IP addresses, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Budibase Query Execution Targeting Internal REST Datasources
    description: Detects execution of queries that use a REST datasource pointing to a private IP address, indicating potential SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical Server-Side Request Forgery (SSRF) vulnerability exists in Budibase version 3.30.6, affecting self-hosted instances that do not explicitly configure the `BLACKLIST_IPS` environment variable. The vulnerability resides within the REST datasource connector and the backend-core blacklist module. Due to the absence of a default IP blacklist, the `isBlacklisted()` function in `packages/backend-core/src/blacklist/blacklist.ts` unconditionally returns `false`, bypassing SSRF protection. This allows users with `Builder` privileges or `QUERY WRITE` permissions to create malicious REST datasources, query internal services, and exfiltrate sensitive data, including CouchDB credentials, application data, and internal service metadata. This vulnerability impacts confidentiality, integrity, and availability, potentially leading to complete instance takeover.

## Attack Chain

1. An attacker with `Builder` privileges logs into the Budibase application.
2. The attacker creates a new REST datasource via `POST /api/datasources`, configuring it to target an internal service like `http://couchdb-service:5984`.
3. The Budibase server, specifically the `packages/server/src/integrations/rest.ts` component, evaluates the URL against the blacklist. Due to the empty `BLACKLIST_IPS`, the `isBlacklisted()` function returns `false`.
4. The REST integration proceeds with the request using the `fetch` API, sending the request to the specified internal service.
5. The internal service (e.g., CouchDB) responds with data.
6. The attacker creates a query via `POST /api/queries` that uses the malicious REST datasource.
7. The attacker executes the query via `POST /api/v2/queries/:id`, triggering a request to the internal service.
8. The response from the internal service, containing sensitive data like database credentials or application data, is returned to the attacker, enabling data exfiltration or further exploitation.

## Impact

Successful exploitation allows attackers to read CouchDB databases, including user credentials (bcrypt password hashes) and platform configurations. They can also modify user records, create new admin accounts, alter application data, or delete databases. The vulnerability enables resource exhaustion, database destruction, and service disruption. The vulnerability crosses the security boundary between the Budibase application layer and the infrastructure layer, granting access to CouchDB, MinIO, Redis, and other internal services.

## Recommendation

*   Immediately set the `BLACKLIST_IPS` environment variable in your Budibase deployment to include at least `127.0.0.1`, private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local addresses (`169.254.0.0/16`), and cloud metadata endpoints to mitigate the SSRF vulnerability.
*   Restrict `BUILDER` role access to only trusted users. Consider using the principle of least privilege for application-level permissions.
*   Deploy the Sigma rule "Detect Budibase REST Datasource Creation Targeting Internal IPs" to your SIEM and tune for your environment to detect potential exploitation attempts.
*   If you have unpatched instances of Budibase and have granted `QUERY WRITE` permissions widely, immediately audit and revoke those permissions from untrusted users.
*   Monitor webserver logs for unusual requests originating from the Budibase application server to internal IP addresses or services, particularly those used by CouchDB, Redis, or MinIO, to identify potential SSRF attempts.
