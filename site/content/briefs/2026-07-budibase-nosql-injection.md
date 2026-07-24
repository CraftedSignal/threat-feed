---
title: Budibase MongoDB NoSQL Injection Vulnerability Allows Data Exfiltration and Remote Code Execution
slug: 2026-07-budibase-nosql-injection
description: A high-severity NoSQL injection vulnerability in Budibase's MongoDB datasource (npm/@budibase/server <= 3.38.1) allows an authenticated BASIC app user to bypass query-level access controls, enabling full collection dumps, arbitrary JavaScript execution via the MongoDB `$where` operator, cross-collection pivots, and arbitrary update/delete operations due to improper handling of Handlebars-enriched JSON queries.
date: "2026-07-24T21:44:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nosql-injection
  - rce
  - data-exfiltration
  - access-control-bypass
  - web-application
vendors:
  - Budibase
products:
  - npm/@budibase/server (<= 3.38.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker exfiltrates any field of any document through the JS expression or via timing side channels. ... arbitrary JavaScript inside the MongoDB server process.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'A BASIC end-user who is only meant to read their own documents reads everyone''s. ... full-collection dump (demonstrated above: three docs returned where the scoped filter returned one, including other users'' secrets).'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'update / delete action types: the filter injection rewrites the affected-document set. One request wipes or rewrites every document the connection can reach.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pmpg-2mxq-6xwr
---

A significant NoSQL injection vulnerability exists within Budibase's MongoDB datasource integration, affecting `npm/@budibase/server` versions up to and including 3.38.1. This flaw allows an authenticated low-privileged BASIC app user to bypass query-level access controls that are designed to scope MongoDB reads (e.g., `{"email": "{{ currentUser.email }}"}`). The vulnerability stems from how Budibase enriches and parses JSON queries; the `noEscaping: true` option during Handlebars enrichment, combined with `JSON.parse` not rejecting duplicate keys, permits an attacker to inject MongoDB operators such as `$ne` or `$comment` into the query's JSON filter. This manipulation effectively rewrites the query sent to MongoDB, allowing the attacker to read all documents in a collection, potentially execute arbitrary JavaScript on the MongoDB server using the `$where` operator, perform cross-collection data access, or even arbitrarily update and delete documents. This vulnerability poses a critical risk to data confidentiality, integrity, and potentially the availability of sensitive information stored in MongoDB databases connected to Budibase applications.

## Attack Chain

1. **Vulnerable Configuration**: A Budibase builder configures a MongoDB datasource query (e.g., `find-by-name`) with a `json` field containing a Handlebars binding like `{"name": "{{name}}"}`.
2. **App Publication and User Assignment**: The builder publishes the application and assigns a BASIC user (e.g., Bob) a role with permissions to execute this query.
3. **Malicious Query Execution**: The BASIC user, Bob, sends an HTTP POST request to the Budibase API endpoint `/api/queries/:queryId` with a crafted JSON payload in the request body.
4. **Handlebars Enrichment and JSON Parsing**: Budibase's server component (`packages/server/src/sdk/workspace/queries/queries.ts`) processes the request. It enriches the query string using Handlebars with `noEscaping: true` and then `JSON.parse`s the result.
5. **Operator Injection via Duplicate Key**: The crafted JSON payload (e.g., `{"parameters":{"name":"x\", \"name\": {\"$ne\": \"x\"}, \"$comment\": \"bud-033"}}`) exploits `JSON.parse`'s behavior of keeping the last value for duplicate keys. This results in an object where a MongoDB operator (like `$ne` for 'not equal') replaces the intended simple value filter.
6. **MongoDB Query Execution**: The modified filter, containing the injected MongoDB operator, reaches the `collection.find` method in `packages/server/src/integrations/mongodb.ts` without proper sanitization.
7. **Access Control Bypass and Data Access**: MongoDB executes the query with the attacker-controlled operator, bypassing the builder's intended per-user access controls (e.g., `{"email": "{{ currentUser.email }}"}`), allowing the user to retrieve all documents from the collection.
8. **Further Exploitation**: Depending on the specific operator injected, the attacker may achieve arbitrary JavaScript execution via `$where` (resulting in arbitrary data exfiltration or system commands on MongoDB server) or perform arbitrary updates/deletions.

## Impact

The primary impact of this vulnerability is the complete circumvention of per-user query filters established by Budibase application builders. A BASIC end-user, who should only see their own records, can read every document in the connected MongoDB collection. This could lead to a full collection dump, exposing other users' sensitive data, administrative records, or any confidential fields stored in the database. The severity escalates if the attacker utilizes specific MongoDB operators: the `$where` operator allows arbitrary JavaScript execution within the MongoDB server process, potentially leading to remote code execution and exfiltration of any field. The `$lookup` operator enables cross-collection joins within the same database, extending data access beyond the initially queried collection. Furthermore, if `update` or `delete` action types are exposed by the builder, the injected filter can be leveraged to wipe or rewrite every document the connection has access to, causing data integrity and availability issues. The blast radius is limited to the builder's own MongoDB deployment, affecting data the Budibase connection can reach.

## Recommendation

* **Patch Immediately**: Upgrade Budibase `npm/@budibase/server` to a version greater than 3.38.1 to address the identified vulnerability. This is the most effective mitigation.
* **Implement WAF/API Gateway Protection**: Deploy a Web Application Firewall (WAF) or API Gateway in front of Budibase applications to inspect HTTP POST request bodies for suspicious NoSQL injection patterns, specifically targeting MongoDB operators like `"$ne"`, `"$comment"`, `"$where"`, or duplicate JSON keys within the `/api/queries/:queryId` endpoint.
* **Enable Application-Level Logging**: Ensure detailed application-level logging is enabled for Budibase API interactions, specifically capturing the full HTTP POST request bodies to the `/api/queries` endpoint. This allows for post-incident analysis and detection of attempted exploitation patterns not covered by network-level logs.
* **Review MongoDB Security Configurations**: Restrict the permissions of the MongoDB user account used by Budibase to the absolute minimum necessary (principle of least privilege) to limit the impact of any successful injection. Avoid granting permissions that allow `$where` or `$eval` if not strictly required.
