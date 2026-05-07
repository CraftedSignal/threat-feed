---
title: Gotenberg SSRF Vulnerability in LibreOffice Conversion Endpoint
slug: 2024-01-02-gotenberg-ssrf
description: Gotenberg is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient hardening in the LibreOffice conversion endpoint, allowing attackers to make outbound HTTP requests by embedding external URLs in uploaded documents, bypassing Gotenberg's SSRF filters, affecting versions up to 8.31.0, and potentially enabling access to internal services, data exfiltration, or port scanning.
date: "2026-05-07T00:57:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - gotenberg
  - libreoffice
  - vulnerability
vendors:
  - Gotenberg
  - LibreOffice
products:
  - Gotenberg (<= 8.31.0)
  - LibreOffice
references:
  - https://github.com/advisories/GHSA-rm4c-xj6x-49mw
iocs:
  - type: url
    value: http://ATTACKER:9877/ssrf
ioc_counts:
  url: 1
rules:
  - title: Detect LibreOffice Outbound Network Connection
    description: Detects LibreOffice processes initiating network connections, which could indicate SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - linux
  - title: Detect External URL in OOXML Relationship File
    description: Detects files containing external URLs inside OOXML relationship files, which could be used for SSRF attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Gotenberg, a Docker-based stateless API for PDF files, is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability in its LibreOffice conversion endpoint. Specifically, the SSRF hardening implemented in version 8.31.0 does not adequately cover LibreOffice's handling of external URLs embedded in uploaded documents. An attacker can craft a malicious document, such as a DOCX file containing external image references, that, when processed by the `/forms/libreoffice/convert` endpoint, causes LibreOffice to make outbound HTTP requests to attacker-controlled servers or internal resources. This bypasses the intended SSRF protections, potentially exposing internal services and sensitive data. This vulnerability was verified on version 8.31.0 using a crafted DOCX file and matters to defenders because it allows attackers to bypass network segmentation and access internal resources normally inaccessible from the internet.

## Attack Chain

1. Attacker crafts a malicious document (e.g., DOCX, XLSX, PPTX, ODT, ODS, ODP, RTF) embedding an external URL reference.
2. The malicious document contains a relationship file (e.g., `word/_rels/document.xml.rels`) with a `TargetMode="External"` attribute pointing to an attacker-controlled URL.
3. The attacker uploads the crafted document to the `/forms/libreoffice/convert` endpoint of a vulnerable Gotenberg instance.
4. Gotenberg's `pkg/modules/libreoffice/routes.go` passes the uploaded document directly to the LibreOffice process via `libreOffice.Pdf()`.
5. LibreOffice parses the document and, due to the external URL reference, initiates an HTTP request to the specified URL.
6. The request bypasses Gotenberg's Go-level SSRF protection mechanisms, as LibreOffice handles the HTTP connection directly using libcurl.
7. LibreOffice makes an HTTP GET request (and potentially an OPTIONS request) to the attacker-controlled server, potentially leaking information through the User-Agent header.
8. The attacker gains access to internal resources, exfiltrates response data, or performs other malicious actions based on the SSRF vulnerability.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to make outbound HTTP requests from the LibreOffice process, potentially reaching internal services and sensitive data. An attacker can target internal services within the container's network, such as localhost or internal IP ranges (10.x, 192.168.x), access cloud metadata at `http://169.254.169.254/` to obtain AWS/GCP/Azure IAM credentials, or perform port scanning of the internal network. The vulnerability affects various document formats, including `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptx`, `.pptm`, `.odt`, `.ods`, `.odp`, `.rtf`. The v8.31.0 SSRF hardening is ineffective, as it only covers Go HTTP calls, not LibreOffice's connections.

## Recommendation

*   Implement network segmentation by running LibreOffice with `unshare --net` to isolate the subprocess and prevent network access. This mitigates the risk of outbound requests, as recommended in the advisory.
*   Develop and deploy a Sigma rule to detect suspicious process execution involving LibreOffice initiating network connections. Use process_creation logs and filter on Image containing "libreoffice" and Initiated: "true".
*   As defense in depth, scan uploaded OOXML files for `_rels/*.rels` entries with `TargetMode="External"` and validate/strip those URLs before passing the file to LibreOffice.
