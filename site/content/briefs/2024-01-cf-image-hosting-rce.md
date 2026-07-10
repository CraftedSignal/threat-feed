---
title: CF Image Hosting Script 1.6.5 Unauthenticated Database Download and Remote Image Deletion
slug: 2024-01-cf-image-hosting-rce
description: CF Image Hosting Script 1.6.5 allows unauthenticated attackers to download the application database, extract delete IDs, and delete all pictures via the `d` parameter.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2019-25709
  - image-hosting
  - unauthorized-access
vendors:
  - CF Image Hosting Script
products:
  - CF Image Hosting Script
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2019-25709
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25709
  - https://www.exploit-db.com/exploits/46094
rules:
  - title: Detect Unauthorized Database Download
    description: Detects unauthorized attempts to download the imgdb.db database file.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Image Deletion Attempt via d Parameter
    description: Detects attempts to delete images using the 'd' parameter in the URL.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CF Image Hosting Script 1.6.5 is vulnerable to an unauthenticated database download vulnerability. An attacker can directly access the `imgdb.db` file located in the `upload/data` directory without any authentication. This database contains sensitive information, including delete IDs stored in plaintext. By extracting these IDs, an attacker can then leverage the `d` parameter in the application to remotely delete any or all images hosted on the platform. The vulnerability was published on April 12, 2026, and could lead to complete image loss and potential denial of service.

## Attack Chain

1.  An unauthenticated attacker sends an HTTP GET request to `/upload/data/imgdb.db` to download the database file.
2.  The web server serves the `imgdb.db` file without authentication.
3.  The attacker downloads the `imgdb.db` file.
4.  The attacker deserializes or opens the database file to extract delete IDs. These IDs are stored in plaintext within the database.
5.  The attacker crafts a malicious URL containing the `d` parameter and the extracted delete IDs, for example, `index.php?d=delete_id_1,delete_id_2`.
6.  The attacker sends the crafted URL to the CF Image Hosting Script server via an HTTP GET request.
7.  The server processes the request and deletes the images associated with the provided delete IDs.

## Impact

Successful exploitation of this vulnerability leads to complete image deletion from the CF Image Hosting Script instance. There is no mention of the number of victims. The impact is high, potentially causing significant data loss and disruption of service for users relying on the image hosting. The vulnerability can be exploited remotely without authentication.

## Recommendation

*   Monitor web server access logs for requests to `/upload/data/imgdb.db` to detect unauthorized database downloads. Deploy the Sigma rule `Detect Unauthorized Database Download` to identify these events.
*   Implement access controls to restrict direct access to the `/upload/data/` directory via the webserver.
*   Apply a web application firewall (WAF) rule to block requests containing the `d` parameter with suspicious delete IDs.
*   Upgrade to a patched version of the CF Image Hosting Script or migrate to a different image hosting solution that addresses this vulnerability.
