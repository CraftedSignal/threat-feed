---
brief_id: brief-2026-06-langflow-rce
event_id: brief-2026-06-langflow-rce
revision: 1
activity_at: "2026-06-16T17:37:40Z"
title: Langflow Unauthenticated RCE in Shareable Playground (CVE-2026-48519)
slug: 2026-06-langflow-rce
description: A critical unauthenticated Remote Code Execution (RCE) vulnerability (CVE-2026-48519) exists in Langflow versions up to and including 1.9.1, allowing attackers to execute arbitrary Python code by sending a crafted JSON payload to the `/api/v1/build_public_tmp` API endpoint of a publicly shared flow.
date: "2026-06-16T17:37:40Z"
lastmod: "2026-10-25T05:40:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LUKEHEBE-IBM-LANGFLOW-CVE-2026-48519-POC&utm_source=rss&utm_medium=rss
tags:
  - langflow
  - rce
  - vulnerability
  - webserver
  - api
vendors:
  - Langflow
products:
  - langflow (<= 1.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
cves:
  - id: CVE-2026-48519
    cvss: 9.6
    epss: 0.00783
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-v5ff-9q35-q26f
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LUKEHEBE-IBM-LANGFLOW-CVE-2026-48519-POC&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-25T05:40:48Z"
    level: L2
    summary: poc_available; added CVE-2026-48519
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-LUKEHEBE-IBM-LANGFLOW-CVE-2026-48519-POC&utm_source=rss&utm_medium=rss
---

A critical security vulnerability, identified as CVE-2026-48519, has been discovered in Langflow, affecting versions up to and including 1.9.1. This unauthenticated Remote Code Execution (RCE) flaw resides within the "Shareable Playground" feature, also referred to as "Public Flows" in the codebase. This feature is designed to allow unauthenticated users to execute workflows via a public link, leveraging the `/api/v1/build_public_tmp` API endpoint. The vulnerability arises because this endpoint fails to properly sanitize or restrict the content within the `data.nodes[X].data.node.template.code.value` field of the JSON payload. An attacker can embed arbitrary Python code in this field, which the Langflow application then executes on the host server. This poses a severe risk, as any Langflow deployment with an active Shareable Playground is susceptible to complete system compromise without prior authentication.

## Attack Chain

1.  An attacker identifies a vulnerable Langflow instance (version <= 1.9.1) that has the "Shareable Playground" feature enabled.
2.  The attacker obtains the unique identifier (flow ID) of a publicly shared flow, typically by accessing the public link of a playground.
3.  The attacker crafts a malicious JSON payload, embedding arbitrary Python code within the `data.nodes[X].data.node.template.code.value` field.
4.  The attacker sends an HTTP POST request to the vulnerable endpoint, `http://<langflow-host>/api/v1/build_public_tmp/<flow-id>/flow`, including the crafted JSON payload in the request body.
5.  The POST request also includes specific query parameters such as `start_component_id` and `event_delivery`, and sets the `Content-Type` header to `application/json`.
6.  The Langflow application processes the request, deserializes the JSON payload, and inadvertently executes the embedded Python code on the host system.
7.  The arbitrary Python code is executed with the privileges of the Langflow application, leading to unauthenticated Remote Code Execution (RCE) and potential compromise of the underlying server.

## Impact

The successful exploitation of CVE-2026-48519 results in unauthenticated Remote Code Execution (RCE) on the server hosting the Langflow application. This allows an attacker to gain full control over the compromised system, leading to severe consequences such as data exfiltration, deployment of additional malware (e.g., ransomware, cryptominers), establishment of persistence mechanisms, or complete disruption of services. All Langflow deployments with an active "Shareable Playground" feature are at critical risk, regardless of the specific flows shared. This vulnerability allows for a complete compromise of the Langflow server and potentially other systems accessible from it.

## Recommendation

*   Patch Langflow to a version greater than 1.9.1 immediately to address CVE-2026-48519.
*   Deploy the Sigma rules provided in this brief to your SIEM or EDR platform to detect exploitation attempts against the vulnerable `/api/v1/build_public_tmp` endpoint.
*   If immediate patching is not possible, disable the "Shareable Playground" feature in your Langflow deployments to mitigate exposure.
*   Ensure web server access logging is enabled for your Langflow application, capturing HTTP method, URI stem, URI query, Content-Type headers, and response status codes to facilitate detection with the provided rules.
