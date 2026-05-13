---
title: Goobi Viewer Unauthenticated Solr Streaming Expression Proxy Vulnerability
slug: 2026-05-goobi-viewer-solr-proxy
description: The Goobi viewer REST endpoint accepted an arbitrary Solr streaming expression from unauthenticated network clients, enabling attackers to read, modify, or delete the complete Solr index; this was resolved by removing the affected API endpoint.
date: "2026-05-13T15:35:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - solr
  - proxy
  - unauthenticated
  - CVE-2026-45083
  - critical
vendors:
  - Intranda
products:
  - Goobi viewer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-2rgp-f66f-4499
  - https://solr.apache.org/guide/solr/latest/query-guide/streaming-expressions.html
rules:
  - title: Detect Goobi Viewer Solr Streaming Expression Attempt
    description: Detects CVE-2026-45083 exploitation — Attempts to access the /api/v1/index/stream endpoint, indicating a potential Solr streaming expression injection attack
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Goobi Viewer Solr Streaming Expression Blocked Attempt
    description: Detects attempts to access the /api/v1/index/stream endpoint after a block is in place, indicated by a 403 or 405 status code
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Goobi viewer is vulnerable to an unauthenticated Solr streaming expression proxy issue. Specifically, the REST endpoint `POST /api/v1/index/stream` was accepting arbitrary Solr streaming expressions from unauthenticated network clients and forwarding them to the backend Solr server without any restrictions. This vulnerability, present in versions 4.8.0 up to and including 26.04, allowed attackers to potentially read the entire Solr index and modify or delete indexed records. The vulnerability has been addressed by removing the affected API endpoint in commit 326980f24c. This vulnerability matters because it could lead to complete data loss or unauthorized disclosure of sensitive data. The CVE assigned to this vulnerability is CVE-2026-45083.

## Attack Chain

1. An unauthenticated attacker sends a POST request to `/api/v1/index/stream` on the Goobi viewer server.
2. The attacker crafts a malicious Solr streaming expression within the body of the POST request.
3. The Goobi viewer forwards the attacker-supplied Solr streaming expression to the backend Solr server.
4. The Solr server executes the streaming expression without proper authorization checks due to the exposed proxy endpoint.
5. Using `select()` the attacker reads the content of the Solr index, including documents protected by access conditions.
6. The attacker uses `update()` streaming expressions to overwrite indexed field values, potentially changing metadata or access conditions.
7. Alternatively, the attacker uses `delete()` streaming expressions to remove documents from the index.
8. If delete is used, the attacker can wipe the entire collection, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability could result in the complete disclosure of all documents indexed by the Goobi viewer, including those protected by access conditions. Attackers could also modify metadata, change access conditions, or corrupt the document structure. A single `delete()` expression can permanently remove documents, potentially leading to complete data loss and requiring a full re-index of the Solr collection. This vulnerability impacts organizations that rely on Goobi viewer to manage and serve sensitive documents.

## Recommendation

*   Apply the patch provided in commit [326980f24c](https://github.com/advisories/GHSA-2rgp-f66f-4499) to remove the vulnerable endpoint.
*   As an immediate workaround, block access to the `/api/v1/index/stream` endpoint using a reverse proxy or Tomcat configuration as detailed in the advisory to prevent exploitation.
*   Deploy the Sigma rule "Detect Goobi Viewer Solr Streaming Expression Attempt" to identify potential exploitation attempts targeting the vulnerable endpoint.
