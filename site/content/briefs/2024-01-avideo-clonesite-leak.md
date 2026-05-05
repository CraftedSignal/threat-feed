---
title: AVideo CloneSite Unauthenticated Information Disclosure Leading to Remote Database Dump
slug: 2024-01-avideo-clonesite-leak
description: AVideo is vulnerable to unauthenticated information disclosure via the `plugin/CloneSite/cloneClient.json.php` endpoint, which echoes the local CloneSite shared secret (`$objClone->myKey`) in HTTP responses without authentication, enabling cross-site database dumps of the configured clone server.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - information_disclosure
  - database_dump
vendors:
  - wwbn
products:
  - avideo (<= 29.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-qm9p-p5pw-jrx2
rules:
  - title: AVideo CloneSite myKey Disclosure in HTTP Response
    description: Detects instances where the CloneSite plugin leaks the myKey in the HTTP response body.
    platform: sigma
    severity: high
    tactics:
      - information_disclosure
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo Remote Database Dump via CloneSite Plugin
    description: Detects access to the database dump file in the videos/clones/ directory after successful exploitation.
    platform: sigma
    severity: critical
    tactics:
      - impact
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, a video sharing platform, is vulnerable to an unauthenticated information disclosure flaw in its CloneSite plugin. The vulnerability resides in the `plugin/CloneSite/cloneClient.json.php` endpoint. This endpoint inadvertently echoes the local CloneSite shared secret (`$objClone->myKey`) in HTTP responses without requiring any form of authentication. This secret is intended to authenticate requests between federated AVideo instances using the CloneSite plugin. An attacker can exploit this vulnerability by simply sending a GET request to the vulnerable endpoint, obtaining the `myKey`. When the AVideo installation is federated with a remote CloneSite server, the attacker can use the leaked `myKey` to impersonate the victim client and trigger a full database dump of the remote server. This database dump includes sensitive information such as user credentials, payment records, and API keys. The vulnerability affects AVideo version 29.0 and earlier.

## Attack Chain

1. The attacker sends an unauthenticated GET request to `https://victim.example.com/plugin/CloneSite/cloneClient.json.php`.
2. The AVideo server echoes the local `$objClone->myKey` within the HTTP response body due to a flawed error message construction.
3. The attacker extracts the leaked `$objClone->myKey` from the response.
4. The attacker crafts a malicious request to the remote CloneSite server (`https://remote-server.example.com/plugin/CloneSite/cloneServer.json.php`) using the leaked `$objClone->myKey` and the victim's URL.
5. The remote CloneSite server validates the attacker's request using the provided key, successfully authenticating the attacker as the victim client.
6. The remote server executes a `mysqldump` command, dumping the entire database (excluding `CachesInDB`) to a publicly accessible directory (`videos/clones/`).
7. The attacker retrieves the database dump from the remote server via an unauthenticated HTTP GET request to `https://remote-server.example.com/videos/clones/Clone_mysqlDump_*.sql`.
8. The attacker analyzes the database dump, gaining access to sensitive information such as user credentials, payment records, and API keys.

## Impact

Successful exploitation of this vulnerability allows any unauthenticated attacker to retrieve the CloneSite shared secret (`myKey`) of any AVideo installation with the CloneSite plugin enabled. When the affected installation is federated with a remote CloneSite server, the attacker can impersonate the victim client and trigger a full database dump of the remote server containing sensitive data. This can lead to the compromise of user accounts, financial information, and sensitive plugin configurations on the remote server. This vulnerability permits unauthorized access to critical data, potentially resulting in severe data breaches and financial losses.

## Recommendation

*   Apply the recommended fix by not echoing the expected key in the rejection message within `plugin/CloneSite/cloneClient.json.php`, and reject non-CLI / non-admin callers cleanly, as detailed in the overview (see code snippet in advisory).
*   Implement the additional hardening recommendations, including replacing the static `myKey` with a randomly generated, per-installation key stored in the plugin configuration that can be rotated.
*   On the remote side (`cloneServer.json.php`), consider requiring the `sqlFile` path to be unguessable (already is, via `uniqid()`) AND gating the dump behind an IP allowlist or an additional pre-shared rotating token.
*   Serve `videos/clones/` with an `.htaccess`/nginx rule that denies direct HTTP access, so that even if a rogue client is authenticated, the dump is not downloadable over the web.
