---
title: OpenEMR XXE Vulnerability (CVE-2026-33913)
slug: 2026-03-openemr-xxe
description: OpenEMR before version 8.0.0.3 is vulnerable to XML External Entity (XXE) injection, allowing an authenticated user with access to the Carecoordination module to upload a crafted CCDA document and read arbitrary files from the server.
date: "2026-03-26T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-33913
  - xxe
  - openemr
  - web-application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33913
  - https://github.com/openemr/openemr/commit/67e1702c41cf486af0069bdafce19860e2cd9a11
  - https://github.com/openemr/openemr/releases/tag/v8_0_0_3
  - https://github.com/openemr/openemr/security/advisories/GHSA-9757-3cfj-wc8q
ioc_counts:
  email: 1
rules:
  - title: Detect XXE Attempt via xi:include Tag
    description: Detects potential XXE attacks by identifying requests containing the `xi:include` tag in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Files via Web Server
    description: Detects attempts to access sensitive files (e.g., /etc/passwd) via web server logs, indicative of XXE or path traversal.
    platform: sigma
    severity: critical
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a free and open-source electronic health records and medical practice management application, is vulnerable to an XML External Entity (XXE) injection attack (CVE-2026-33913). This vulnerability affects versions prior to 8.0.0.3. An authenticated user with access to the Carecoordination module can exploit this flaw by uploading a specially crafted CCDA document. The malicious document contains an `xi:include` tag that references a file on the server (e.g., `/etc/passwd`), enabling the…
