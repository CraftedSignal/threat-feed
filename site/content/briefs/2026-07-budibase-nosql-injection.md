---
title: Budibase NoSQL Operator Injection (CVE-2026-54350)
slug: 2026-07-budibase-nosql-injection
description: An unauthenticated attacker can exploit CVE-2026-54350, a NoSQL operator injection vulnerability in Budibase server versions prior to 3.39.12, by injecting malicious parameters into public-facing query templates, enabling them to bypass intended query filters, read all documents including sensitive information, and modify all documents within affected collections with a single HTTP request.
date: "2026-07-03T11:21:33Z"
lastmod: "2026-07-07T02:03:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:budibase:budibase:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=E7208285-7740-58AA-9601-BD03EDB2275F&utm_source=rss&utm_medium=rss
tags:
  - nosql-injection
  - web-vulnerability
  - budibase
  - data-exfiltration
  - data-manipulation
  - critical-vulnerability
  - api-exploitation
vendors:
  - Budibase
products:
  - Budibase server (< 3.39.12)
  - '@budibase/server (< 3.39.12)'
  - Budibase (< 3.39.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: '`authorized` middleware at `packages/server/src/middleware/authorized.ts:141-148` short-circuits when the query''s role is `PUBLIC`. `POST /api/v2/queries/:queryId` (`packages/server/src/api/routes/query.ts:63`) accepts the call with no session, only an `x-budibase-app-id` header that is public from the published-app URL.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Stolen Data
    evidence: Anonymous read of every document in any backing MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body collection reachable through a `PUBLIC` query, including columns the published query was not designed to return (`password_hash`, `secret`, `api_token`, `mfa_secret`).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Anonymous modification of every document of that collection where the builder has published a `PUBLIC` `update`, `delete`, or `aggregate` query, beyond the builder's intended single-document scope.
    confidence_band: high
cves:
  - id: CVE-2026-54350
    cvss: 10
    epss: 0.00538
references:
  - https://github.com/advisories/GHSA-8qv3-p479-cj62
  - https://sploitus.com/exploit?id=E7208285-7740-58AA-9601-BD03EDB2275F&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=E7208285-7740-58AA-9601-BD03EDB2275F
  - type: url
    value: https://github.com/Budibase/budibase/security/advisories/GHSA-8qv3-p479-cj62
  - type: other
    value: zzz","name":{"$exists":true},"$comment":"cve-2026-54350
ioc_counts:
  other: 1
  url: 2
rules:
  - title: Detect CVE-2026-54350 Exploitation — Budibase NoSQL Operator Injection Attempt
    description: Detects CVE-2026-54350 exploitation — crafted JSON injection patterns in POST requests to Budibase public query API endpoints indicating NoSQL operator injection attempts.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1485
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-07T02:03:42Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
---

A critical NoSQL operator injection vulnerability, tracked as CVE-2026-54350, affects Budibase server versions up to 3.39.0 (and npm package `@budibase/server` versions `< 3.39.12`). This flaw stems from improper input validation and handling within the `enrichContext` and `validateQueryInputs` functions when processing query templates for MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body datasources. An unauthenticated attacker can craft a malicious JSON payload in a parameter value that contains specific JSON metacharacters. When this payload is substituted into a raw JSON query body and subsequently parsed, it can overwrite the intended query logic, such as a `{name: "..."}` filter being replaced by `{name: {$exists: true}}`. This allows the attacker to read and modify entire database collections, including sensitive data, using a single HTTP request to a publicly accessible API endpoint, without requiring authentication or bypassing CSRF protections.

## Attack Chain

1.  An attacker identifies a published Budibase application that uses a non-SQL datasource (MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body) and has a `PUBLIC` role assigned to at least one query (e.g., `GetUserByName`).
2.  The attacker, unauthenticated, sends an HTTP `POST` request to `/api/v2/queries/:queryId` for the identified public read query, including an `x-budibase-app-id` header.
3.  The request body contains a JSON payload with the `parameters` field where a parameter (e.g., `name`) is injected with a crafted string like `x",\"name\":{\"$exists\":true},\"$comment\":\"audit"`.
4.  Budibase's `enrichContext` function substitutes this raw parameter value directly into the query's JSON body string without proper JSON-string escaping.
5.  The subsequent `JSON.parse` operation on the malformed string results in a parsed filter object (e.g., `collection.find()`) where the attacker's injected `$exists:true` clause overrides the legitimate filter, effectively widening the scope to return all documents.
6.  The Budibase server returns all documents from the collection, including sensitive fields not intended for public exposure (e.g., `password_hash`, `secret`), to the unauthenticated attacker.
7.  If a `PUBLIC` write query (e.g., `updateMany`) is available, the attacker can similarly inject a payload to widen the `filter` scope, causing the `updateMany` operation to affect all documents in the collection, leading to widespread data modification or destruction.

## Impact

Successful exploitation of CVE-2026-54350 allows an unauthenticated visitor to conduct broad data breaches and integrity compromises. This includes the anonymous reading of every document within any MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body collection exposed via a `PUBLIC` query. Attackers can exfiltrate sensitive data such as `password_hash`, `secret`, `api_token`, and `mfa_secret` from columns not intended to be returned. Furthermore, where a `PUBLIC` `update`, `delete`, or `aggregate` query exists, attackers can anonymously modify or destroy every document in that collection, extending beyond the original builder's intended single-document scope. All of this can be achieved with a single HTTP request, bypassing session and CSRF protections.

## Recommendation

*   **Patch CVE-2026-54350 immediately:** Upgrade your Budibase server instances to version 3.39.12 or newer to remediate the vulnerability. Refer to the official Budibase release notes and patching guidance.
*   **Deploy the provided Sigma rule:** Implement the `Detect CVE-2026-54350 Exploitation` Sigma rule in your SIEM to identify attempts at NoSQL operator injection against your Budibase applications.
*   **Monitor webserver logs:** Specifically look for `POST` requests to `/api/v2/queries/:queryId` containing JSON body parameters with suspicious injection patterns (e.g., `",\\\"$exists\\\":true"`) in `cs-uri-query` or equivalent fields.
*   **Audit public queries:** Review all `PUBLIC` role-assigned queries in your Budibase applications, especially those interacting with MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body datasources, to ensure sensitive data is not inadvertently exposed or modifiable.
