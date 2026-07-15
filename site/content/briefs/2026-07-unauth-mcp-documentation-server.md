---
title: Unauthenticated Access to @andrea9293/mcp-documentation-server Web UI/API
slug: 2026-07-unauth-mcp-documentation-server
description: The `@andrea9293/mcp-documentation-server` version 1.13.0 defaults to binding its Web UI/API to all network interfaces (0.0.0.0:3080) and lacks authentication for its document-management endpoints, enabling any network-reachable attacker to perform unauthorized operations such as reading, searching, adding, and deleting documents, potentially corrupting the user's knowledge base.
date: "2026-07-15T23:28:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web
  - api
  - node.js
  - default-misconfiguration
  - unauthenticated-access
vendors:
  - andrea9293
products:
  - '@andrea9293/mcp-documentation-server'
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Web UI/API appears to bind to all network interfaces by default (`*:3080` / `0.0.0.0:3080`) instead of localhost-only, and its document-management API endpoints do not require authentication.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: In my reproduction, I was able to enumerate documents, add a document, read its full content, search across the corpus, and delete the document through the host's LAN IP.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: 'A network-reachable attacker can access the document-management API without credentials. Depending on what the user stores in the documentation server, this may allow: ... inserting attacker-controlled documents into the corpus;'
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: 'A network-reachable attacker can access the document-management API without credentials. Depending on what the user stores in the documentation server, this may allow: ... deleting documents;'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6f5r-5672-72j7
rules:
  - title: Detect Unauthenticated Access to MCP Documentation Server API
    description: Detects CVE-2026-54504 exploitation - unauthenticated network access to sensitive API endpoints of the @andrea9293/mcp-documentation-server. This indicates a network-reachable attacker interacting with the server without credentials.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
      - initial_access
    techniques:
      - T1190
      - T1485
      - T1530
      - T1565.001
    data_sources:
      - webserver
rules_count: 1
---

The `@andrea9293/mcp-documentation-server` version 1.13.0 contains a critical vulnerability, tracked as CVE-2026-54504, where its Web UI and API bind to all network interfaces (`0.0.0.0:3080`) by default without requiring any authentication for document management endpoints. This configuration flaw exposes sensitive document operations - including reading, searching, adding, and deleting documents - to any client on the same local area network (LAN), virtual machine network, or container bridge. This issue is not the existence of a Web UI but its default unsafe exposure, allowing uncredentialed access to an application that could contain private or sensitive data. The vulnerability was published on July 15, 2026, and affects users running the server on various platforms such as laptops, workstations, or VMs connected to shared networks. This could lead to data exposure, tampering, or destruction of the user's local knowledge base.

## Attack Chain

1. **Network Discovery**: An attacker scans local networks (LAN, VM networks, Docker bridges) for open ports, specifically identifying systems listening on port `3080/TCP`.
2. **Service Identification**: Upon finding an open port `3080/TCP`, the attacker sends a benign HTTP GET request to a known public endpoint like `/api/config` to confirm that the `@andrea9293/mcp-documentation-server` Web UI/API is running and network-accessible.
3. **Unauthenticated Access**: The attacker attempts to interact with document management API endpoints (e.g., `/api/documents`, `/api/search-all`) without providing any authentication credentials (e.g., no `Authorization` header).
4. **Information Disclosure**: The attacker sends unauthenticated HTTP GET requests to `/api/documents` and `/api/documents/:id` to enumerate and read the content of stored documents.
5. **Data Manipulation**: The attacker sends unauthenticated HTTP POST requests to `/api/documents` to insert new, attacker-controlled documents into the server's corpus.
6. **Corpus Search**: The attacker leverages the unauthenticated `/api/search-all` endpoint with specific queries to search across the entire document corpus, potentially extracting sensitive information.
7. **Data Destruction**: The attacker sends unauthenticated HTTP DELETE requests to `/api/documents/:id` to delete existing documents from the server.
8. **Impact on Knowledge Base**: Through these actions, the attacker can read, add, modify, or delete documents, effectively tampering with or destroying the user's local knowledge base used by the MCP assistant.

## Impact

The described vulnerability allows a network-reachable attacker to gain full administrative access to the document management API without any credentials. This can lead to significant impact depending on the nature of the data stored in the documentation server. Attackers can read sensitive document titles, previews, and full contents, search the entire corpus for specific information, insert malicious or misleading documents, and delete existing documents. This could result in information disclosure, data integrity compromise, and data loss. Users running the MCP server on shared networks, virtual machines, or local development environments are particularly vulnerable, as an attacker on the same network segment can exploit this flaw to corrupt or exfiltrate the user's local knowledge base.

## Recommendation

* **Deploy the Sigma rule to detect suspicious API access**: Deploy the `Detect Unauthenticated Access to MCP Documentation Server API` rule to your SIEM to alert on any non-localhost access to the sensitive API endpoints (`/api/documents`, `/api/search-all`, `/api/config`) on port 3080.
* **Monitor webserver logs**: Monitor `webserver` logs for HTTP requests to `/api/documents`, `/api/search-all`, and `/api/config` originating from non-localhost IP addresses, particularly on port 3080.
* **Implement network segmentation**: Restrict network access to port 3080 on hosts running the `@andrea9293/mcp-documentation-server` to only trusted internal IP addresses or `localhost` as described in CVE-2026-54504.
* **Apply vendor patches**: Refer to the advisory at `https://github.com/advisories/GHSA-6f5r-5672-72j7` for any future patches or configuration guidance from the vendor to bind the service to `127.0.0.1` by default or enable authentication.
