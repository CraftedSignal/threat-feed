---
title: Pimcore WebDAV Asset MOVE Missing Authorization Vulnerability
slug: 2026-05-pimcore-webdav-asset-move
description: Pimcore's WebDAV asset endpoint exposes a `MOVE` operation without authentication, allowing unauthenticated remote attackers to delete assets if they know two existing asset paths in the same directory; Authenticated low-privileged users may also be able to perform unauthorized asset move or overwrite operations because the move path does not enforce `rename`, `delete`, `create`, or `publish` permissions, leading to data loss, content integrity loss, and service disruption.
date: "2026-05-27T17:20:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webdav
  - asset-management
  - missing-authorization
  - pimcore
vendors:
  - Pimcore
products:
  - pimcore/pimcore (<= 12.3.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-wc7j-g8wx-m2qx
  - CVE-2026-45260
rules:
  - title: Detect Pimcore WebDAV Unauthorized Asset MOVE
    description: Detects CVE-2026-45260 exploitation — WebDAV MOVE requests to the /asset/webdav endpoint indicating potential unauthorized asset deletion
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Pimcore WebDAV Asset MOVE with Overwrite
    description: Detects CVE-2026-45260 exploitation — WebDAV MOVE requests to the /asset/webdav endpoint with the Overwrite header set, indicating potential unauthorized asset replacement.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Pimcore, a PHP-based platform for managing digital data, contains a vulnerability in its WebDAV asset endpoint that allows unauthorized asset manipulation. The vulnerability, identified as CVE-2026-45260, stems from a missing authentication plugin in the WebDAV controller, specifically impacting the `MOVE` operation. This oversight enables unauthenticated remote attackers, who possess knowledge of two existing asset paths within the same directory, to send a crafted WebDAV request and delete the source asset. Moreover, authenticated low-privileged users can exploit this flaw to perform unauthorized asset move or overwrite operations due to the absence of proper permission checks along the move path. This can lead to data loss and service disruption. The affected versions are Pimcore 12.3.6 and earlier.

## Attack Chain

1. An unauthenticated attacker identifies two existing asset paths in the same directory on a Pimcore instance (e.g., `/products/source.jpg` and `/products/existing.jpg`).
2. The attacker crafts a WebDAV `MOVE` request targeting the source asset (`/products/source.jpg`).
3. The `Destination` header of the `MOVE` request is set to the path of the destination asset (`/products/existing.jpg`).
4. The `Overwrite` header is set to `T`, indicating that the destination asset should be overwritten if it exists.
5. The attacker sends the crafted `MOVE` request to the `/asset/webdav` endpoint.
6. The Pimcore server receives the request and, due to the missing authentication plugin, processes it without verifying the attacker's identity.
7. The `Tree::move()` function is executed, which deletes the source asset (`/products/source.jpg`) via the `Asset::delete()` function *before* checking for a valid user session or asset permissions.
8. The server attempts to set the `userModification` field but fails because there's no authenticated user, triggering an error. Despite the error, the source asset has already been deleted.

## Impact

This vulnerability allows for the unauthorized deletion of assets in Pimcore. An unauthenticated attacker can remotely delete assets if they know the paths. In Pimcore deployments where assets represent product images, documents, media, or DAM-managed business content, this deletion or unauthorized overwrite can cause data loss, content integrity loss, and service disruption. The affected package is `composer/pimcore/pimcore` in versions 12.3.6 and earlier.

## Recommendation

*   Apply the necessary patches to upgrade Pimcore to a version greater than 12.3.6 to address CVE-2026-45260.
*   Deploy the Sigma rule "Detect Pimcore WebDAV Unauthorized Asset MOVE" to identify potential exploitation attempts against the `/asset/webdav` endpoint.
*   Monitor web server logs for `MOVE` requests targeting the `/asset/webdav` endpoint as described in the attack chain.
