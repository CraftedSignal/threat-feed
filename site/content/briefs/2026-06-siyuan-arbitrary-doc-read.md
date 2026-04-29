---
title: SiYuan Arbitrary Document Reading Vulnerability in Publishing Service
slug: 2026-06-siyuan-arbitrary-doc-read
description: SiYuan is vulnerable to arbitrary document reading via the publishing service, allowing attackers to retrieve document IDs and view the content of all documents, including encrypted or prohibited ones, by exploiting the `/api/file/readDir` and `/api/block/getChildBlocks` interfaces.
date: "2026-03-25T19:37:18Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - siyuan
  - arbitrary-document-access
  - vulnerability
  - webserver
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/advisories/GHSA-34xj-66v3-6j83
rules:
  - title: SiYuan Arbitrary Document Access via getChildBlocks
    description: Detects potential exploitation of the SiYuan arbitrary document access vulnerability by monitoring requests to the /api/block/getChildBlocks endpoint.
    platform: sigma
    severity: critical
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: SiYuan Document ID Enumeration via readDir
    description: Detects potential document ID enumeration attempts by monitoring requests to the /api/file/readDir endpoint.
    platform: sigma
    severity: medium
    tactics:
      - information_gathering
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan, a note-taking application, is susceptible to an arbitrary document reading vulnerability within its publishing service. This flaw allows an unauthenticated attacker to bypass access controls and retrieve the content of any document, regardless of encryption or access restrictions. The vulnerability stems from inadequate authorization checks when accessing document content through specific API endpoints. The issue was reported on March 25, 2026, and is tracked as CVE-2026-33669. The vulnerable package is `go/github.com/siyuan-note/siyuan/kernel`, specifically versions equal to or older than `0.0.0-20260317012524-fe4523fff2c8`. This vulnerability poses a significant risk to organizations and individuals using SiYuan for sensitive data storage, potentially leading to unauthorized access and data breaches.

## Attack Chain

1.  The attacker identifies a SiYuan instance with the publishing service enabled.
2.  The attacker sends a request to the `/api/file/readDir` endpoint to retrieve a list of document IDs. This endpoint lacks proper authorization checks.
3.  The SiYuan server responds with a list of document IDs available within the publishing service.
4.  The attacker selects a target document ID from the list obtained in the previous step.
5.  The attacker sends a POST request to the `/api/block/getChildBlocks` endpoint, providing the target document ID in the request body. This endpoint is intended to retrieve child blocks of a specific document.
6.  Due to insufficient access control, the server processes the request and returns the content of the requested document, even if it is encrypted or restricted.
7.  The attacker parses the JSON response to extract the document content, which is typically formatted in Markdown.
8. The attacker can repeat steps 4-7 to obtain the content of other documents.

## Impact

The arbitrary document reading vulnerability allows unauthorized access to potentially sensitive information stored within SiYuan. Successful exploitation could lead to the disclosure of confidential documents, intellectual property, personal data, or other restricted content. The impact is significant, as it bypasses intended security measures such as encryption and access controls. While specific victim numbers are unknown, any organization or individual utilizing the affected SiYuan version with the publishing service enabled is potentially at risk. The CVE is rated critical.

## Recommendation

*   Upgrade SiYuan to a patched version that addresses CVE-2026-33669.
*   Deploy the Sigma rule "SiYuan Arbitrary Document Access via getChildBlocks" to detect potential exploitation attempts targeting the `/api/block/getChildBlocks` endpoint in your web server logs.
*   Monitor web server logs for suspicious activity, specifically POST requests to `/api/block/getChildBlocks` with unusual document IDs or request patterns.
*   Implement rate limiting on the `/api/file/readDir` and `/api/block/getChildBlocks` endpoints to mitigate potential abuse.
* Enable webserver logging and ensure all SiYuan instances are monitored by the logging solution.
