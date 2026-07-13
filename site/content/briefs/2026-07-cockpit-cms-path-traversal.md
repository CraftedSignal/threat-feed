---
title: CVE-2026-57856 - Cockpit CMS Path Traversal Vulnerability
slug: 2026-07-cockpit-cms-path-traversal
description: A path traversal vulnerability (CVE-2026-57856) exists in the Bucket file storage API of Cockpit CMS, allowing authenticated low-privileged users to exploit a flaw in bucket name sanitization to access, upload, or delete files across all buckets by using crafted '..' sequences.
date: "2026-07-13T23:18:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - privilege-escalation
  - data-exfiltration
  - api-abuse
vendors:
  - Cockpit CMS
products:
  - Cockpit CMS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An authenticated low-privileged user can send a crafted request... to list, upload, and delete files across all buckets, including those belonging to other users or roles
    confidence_band: high
cves:
  - id: CVE-2026-57856
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57856
rules:
  - title: Detect CVE-2026-57856 Exploitation - Cockpit CMS Path Traversal
    description: Detects CVE-2026-57856 exploitation - path traversal attempts targeting the Cockpit CMS Bucket file storage API by looking for '..' or '..%2f' sequences in the URI stem or query.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-57856, has been identified in the Cockpit CMS Bucket file storage API, specifically within the `/system/buckets/api` endpoint. This flaw stems from inadequate sanitization of the `bucket` name by the `api()` method in `modules/System/Controller/Buckets.php`, which fails to correctly strip '..' and '../' sequences. When this unsafely sanitized bucket name is interpolated into a Flysystem path as `uploads://buckets/{bucket}`, the Flysystem `WhitespacePathNormalizer` resolves `buckets/..` to the storage root. This bypass allows an authenticated low-privileged user to craft requests that grant unauthorized listing, uploading, and deletion of files across all buckets within the CMS, including those belonging to other users or administrative roles, posing a significant risk of data exfiltration, integrity compromise, and potential privilege escalation.

## Attack Chain

1. An authenticated low-privileged user gains access to the Cockpit CMS application.
2. The attacker identifies the vulnerable Bucket file storage API located at the `/system/buckets/api` endpoint.
3. The attacker crafts an HTTP request to this API, embedding a path traversal sequence such as `../` or its URL-encoded equivalent `..%2f` within the supplied bucket name parameter.
4. The server-side `api()` method within `modules/System/Controller/Buckets.php` receives the crafted request, attempting to sanitize the bucket name.
5. The `preg_replace('/[^a-zA-Z0-9-_\\.]/','', $bucket)` sanitization function fails to neutralize the `../` sequences, leaving them intact.
6. The incompletely sanitized bucket name is then used to construct an internal Flysystem path, resulting in a URI-like string such as `uploads://buckets/{bucket_with_traversal_sequences}`.
7. Flysystem's `WhitespacePathNormalizer` processes this path, inadvertently resolving the `buckets/..` segment to the root of the storage system, effectively bypassing intended access restrictions.
8. The attacker can now perform unauthorized operations, including listing, uploading, and deleting files, across any bucket within the Cockpit CMS environment, potentially leading to data theft or compromise of the application.

## Impact

Successful exploitation of CVE-2026-57856 allows an authenticated, low-privileged user to gain unauthorized access and control over all file storage buckets in the Cockpit CMS instance. This includes the ability to list the contents of any bucket, upload arbitrary files, and delete existing files, regardless of ownership or assigned user roles. This could lead to severe data integrity issues, unauthorized data exfiltration of sensitive information, or even remote code execution if malicious files are uploaded and subsequently executed by the server. The broad access afforded to a low-privileged user significantly elevates the risk profile for organizations utilizing Cockpit CMS, potentially exposing all stored data to compromise.

## Recommendation

* Patch CVE-2026-57856 on all Cockpit CMS instances immediately to prevent exploitation.
* Deploy the `Detect CVE-2026-57856 Exploitation - Cockpit CMS Path Traversal` Sigma rule to your SIEM to detect attempts at exploiting the `/system/buckets/api` endpoint.
* Enable comprehensive web server logging for the `webserver` category, capturing `cs-uri-stem`, `cs-uri-query`, and `cs-method`, to ensure the log source for the detection rule is available.
