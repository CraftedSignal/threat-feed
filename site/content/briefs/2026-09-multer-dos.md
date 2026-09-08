---
title: Denial of Service in multer via Crafted Multipart Field Names
slug: 2026-09-multer-dos
description: An unauthenticated remote attacker can crash Node.js applications using the multer package by sending a specifically crafted multipart/form-data request that triggers an uncaught RangeError.
date: "2026-09-08T21:49:34Z"
lastmod: "2026-09-08T21:49:47Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:multer_project:multer:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:expressjs:multer:*:*:*:*:*:node.js:*:*
products:
  - multer (< 2.3.0)
  - multer (2.2.0)
cves:
  - id: CVE-2026-77078
    cvss: 7.5
    epss: 0.00291
references:
  - https://github.com/advisories/GHSA-wc9g-mqfw-jrwm
  - https://github.com/advisories/GHSA-qfvm-cv95-jqjf
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-77037
  - https://github.com/advisories/GHSA-535w-7cp7-47q4
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-82333
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  mitigation_plan:
    - priority: immediate
      action: Upgrade multer dependency to 2.3.0 or later
      owner: Development
      addresses: CVE-2026-77078
      evidence: Users should upgrade to 2.3.0.
updates:
  - at: "2026-09-08T21:49:41Z"
    level: L1
    summary: added coverage for multer (2.2.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-qfvm-cv95-jqjf
  - at: "2026-09-08T21:49:47Z"
    level: L1
    summary: added coverage for multer (< 2.3.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-535w-7cp7-47q4
---

The npm package 'multer', a common middleware for handling 'multipart/form-data' in Node.js applications, contains a high-severity vulnerability tracked as CVE-2026-77078. The issue stems from an improper handling of multipart field names within the library's parsing logic. By providing two specially crafted text field names in a single request, a remote, unauthenticated attacker can force an uncaught 'RangeError: Invalid array length' during the parsing phase. Because this error occurs outside of the application's defined error handling middleware or global try-catch blocks, it results in the immediate termination of the Node.js process. This vulnerability affects all applications utilizing multer versions prior to 2.3.0 for processing multipart uploads, posing a significant risk of service disruption for web applications.

## Impact

Successful exploitation leads to an immediate crash of the Node.js process, causing a complete denial of service for the affected application. Given the ubiquity of multer in the Node.js ecosystem, any web service accepting file uploads or form data is potentially vulnerable. There are no known workarounds, necessitating an immediate upgrade to the patched version.

## Recommendation

Update the 'multer' dependency in all Node.js projects to version 2.3.0 or later to include the patch for CVE-2026-77078.
