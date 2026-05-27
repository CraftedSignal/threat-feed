---
title: Pimcore Unsafe PHP Deserialization Vulnerability (CVE-2026-45162)
slug: 2026-05-pimcore-deserialization
description: Pimcore v11 and earlier is vulnerable to unsafe PHP deserialization in multiple locations due to missing `allowed_classes` restrictions when calling `unserialize()` on data from database columns and filesystem files; an attacker with control over serialized data sources (e.g., via SQL injection or file write vulnerabilities) can inject PHP gadget chains, leading to remote code execution.
date: "2026-05-27T16:58:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - remote code execution
  - php
vendors:
  - Pimcore
products:
  - pimcore/pimcore
  - pimcore/admin-ui-classic-bundle
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-36fc-7wjg-mfvj
  - CVE-2026-45162
rules:
  - title: Detect CVE-2026-45162 Exploitation Attempt - WebDAV Delete Log Modification
    description: Detects CVE-2026-45162 exploitation attempt by monitoring for modifications to the WebDAV delete log file with suspicious content.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
  - title: Detect CVE-2026-45162 Exploitation Attempt - Suspicious Data in TmpStore
    description: Detects CVE-2026-45162 exploitation attempt by monitoring for writes to the `tmp_store` table containing serialized PHP objects.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Pimcore, a content management framework, contains a critical vulnerability (CVE-2026-45162) due to unsafe PHP deserialization in version 11 and earlier. The vulnerability stems from the use of `unserialize()` in multiple locations without the `allowed_classes` restriction. This oversight allows attackers to inject arbitrary PHP objects if they can control the serialized data. The affected locations include `lib/Tool/Authentication.php`, `models/Site/Dao.php`, `models/DataObject/ClassDefinition/CustomLayout/Dao.php`, `models/Tool/TmpStore/Dao.php`, `models/Asset/WebDAV/Service.php`, and `admin-ui-classic-bundle/src/Helper/Dashboard.php`. The data being deserialized is sourced from database columns and filesystem files. Exploitation requires an attacker to be able to write to these data sources, which can be achieved through SQL injection or file write vulnerabilities. Successful exploitation leads to remote code execution.

## Attack Chain

1.  The attacker identifies a writable data source, such as the `tmp_store` table or the `webdav-delete.dat` file.
2.  The attacker gains write access to the chosen data source, for example via SQL injection against the `tmp_store` table or a file write vulnerability against `webdav-delete.dat`.
3.  The attacker crafts a malicious serialized PHP object, containing a gadget chain designed for remote code execution (e.g., using Monolog's BufferHandler).
4.  The attacker writes the malicious serialized data to the targeted data source (e.g., inserting a row into `tmp_store` with the serialized payload, or writing to `webdav-delete.dat`).
5.  A user action or scheduled task triggers the vulnerable `unserialize()` call in one of the affected files (e.g., accessing a page that reads from `TmpStore`, or triggering a WebDAV operation that uses the delete log).
6.  The PHP `unserialize()` function processes the attacker-controlled serialized data without `allowed_classes`.
7.  The injected PHP object is instantiated, and its methods are invoked according to the gadget chain.
8.  The gadget chain executes arbitrary PHP code with the privileges of the web server, resulting in remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary PHP code on the Pimcore server. This can lead to complete compromise of the application, including data theft, modification, or deletion. The impact is amplified by the availability of public exploit techniques and gadget chains. Given Pimcore's use in content management and e-commerce, a successful attack could have significant financial and reputational consequences.

## Recommendation

*   Apply the vendor-supplied patch or upgrade to a version of Pimcore that addresses CVE-2026-45162.
*   Deploy the Sigma rules provided in this brief to your SIEM and tune them for your environment to detect potential exploitation attempts.
*   Monitor web server logs for suspicious activity related to database access (e.g., SQL injection attempts) that could be used to inject malicious serialized data into database tables.
*   Implement strict file permission controls on the web server to prevent unauthorized writing to the filesystem, mitigating the risk of injecting serialized data into files like `webdav-delete.dat`.
