---
title: SiYuan Unauthorized Attribute View Deletion Vulnerability (CVE-2026-40259)
slug: 2024-01-10-siyuan-attribute-deletion
description: SiYuan versions 3.6.3 and below are vulnerable to unauthorized attribute view deletion via the /api/av/removeUnusedAttributeView endpoint, allowing authenticated users with publish-service RoleReader tokens to delete arbitrary attribute view definitions, leading to database view breakage and workspace rendering issues.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - siyuan
  - attribute-deletion
  - vulnerability
  - webserver
vendors:
  - SiYuan
products:
  - SiYuan
cves:
  - id: CVE-2026-40259
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40259
rules:
  - title: SiYuan Suspicious Attribute View Deletion
    description: Detects suspicious POST requests to the /api/av/removeUnusedAttributeView endpoint in SiYuan, indicating potential unauthorized attribute view deletion attempts.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: SiYuan Suspicious Attribute View Deletion - Status Code
    description: Detects suspicious POST requests to the /api/av/removeUnusedAttributeView endpoint in SiYuan, indicating potential unauthorized attribute view deletion attempts that might result in a 500 error.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan, an open-source personal knowledge management system, is susceptible to an unauthorized attribute view deletion vulnerability. Specifically, versions 3.6.3 and earlier are affected by CVE-2026-40259. The vulnerability resides in the `/api/av/removeUnusedAttributeView` endpoint. This endpoint is inadequately protected, relying solely on generic authentication that accepts publish-service RoleReader tokens. An attacker with a valid RoleReader token can exploit this flaw to permanently delete arbitrary attribute view definitions, causing data corruption. This issue was resolved in SiYuan version 3.6.4, underscoring the importance of promptly updating to the latest version. The scope of targeting includes any SiYuan instance running a vulnerable version, potentially affecting any user relying on the system for knowledge management.

## Attack Chain

1.  Attacker obtains a valid publish-service RoleReader token for a SiYuan instance running version 3.6.3 or below.
2.  Attacker identifies the `data-av-id` value of a target attribute view from publicly exposed or accessible content within the SiYuan workspace.
3.  Attacker crafts a malicious HTTP POST request to the `/api/av/removeUnusedAttributeView` endpoint, including the compromised RoleReader token for authentication.
4.  The POST request contains the target `data-av-id` value within the request body, specifically targeting a attribute view for deletion.
5.  The SiYuan server, failing to properly validate the attacker's privileges and the attribute view's usage, passes the attacker-controlled `data-av-id` directly to a model function.
6.  The model function unconditionally deletes the corresponding attribute view file from the workspace's storage.
7.  Affected database views and the workspace rendering become broken or corrupted due to the missing attribute view definition.
8.  The attacker achieves their objective of disrupting the SiYuan instance by deleting arbitrary attribute view definitions, requiring manual restoration of the database and workspace.

## Impact

Successful exploitation of CVE-2026-40259 can lead to the permanent deletion of arbitrary attribute view definitions within a SiYuan workspace. This results in broken database views and workspace rendering, requiring manual intervention to restore functionality. While the specific number of potential victims is unknown, any organization or individual utilizing SiYuan versions 3.6.3 and below is vulnerable. The impact includes data integrity issues, service disruption, and potential data loss if backups are not available.

## Recommendation

*   Immediately upgrade all SiYuan installations to version 3.6.4 or later to remediate CVE-2026-40259.
*   Implement the Sigma rule "SiYuan Suspicious Attribute View Deletion" to detect potential exploitation attempts targeting the `/api/av/removeUnusedAttributeView` endpoint.
*   Monitor web server logs for POST requests to the `/api/av/removeUnusedAttributeView` endpoint with unusual or unexpected `data-av-id` values.
*   Review and restrict publish-service RoleReader token permissions to minimize the potential impact of compromised credentials.
