---
title: Pterodactyl Wings Privilege Escalation via Improper JWT Scoping (CVE-2026-54593)
slug: 2026-07-pterodactyl-jwt-scoping
description: A privilege escalation vulnerability, CVE-2026-54593, exists in Pterodactyl's Wings component that allows authenticated subusers to upload arbitrary files to a server without explicit file creation permissions, due to insufficient validation of panel-signed JSON Web Tokens (JWTs.
date: "2026-07-28T15:44:29Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Unauthorized Subuser
tags:
  - privilege-escalation
  - vulnerability
  - JWT
  - Pterodactyl
  - web-server
vendors:
  - Pterodactyl
products:
  - Pterodactyl Panel (< 1.12.3)
  - Pterodactyl Wings (< 1.12.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A privilege escalation vulnerability exists in the Wings /upload/file endpoint due to insufficient validation of panel-signed JWTs. ... an authenticated subuser can reuse one of those tokens to upload arbitrary files without possessing the required `file.create` permission.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8r6w-3qq5-4p4r
rules:
  - title: Detect CVE-2026-54593 Exploitation - Unauthorized Pterodactyl File Upload
    description: Detects CVE-2026-54593 exploitation where a subuser attempts to upload files to Pterodactyl Wings via the /upload/file endpoint using a JWT token, potentially indicating privilege escalation due to improper JWT scoping.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

A significant privilege escalation vulnerability, tracked as CVE-2026-54593, affects Pterodactyl Panel versions prior to 1.12.3 and Pterodactyl Wings versions prior to 1.12.2. The flaw resides in the Wings `/upload/file` endpoint, which improperly validates panel-signed JSON Web Tokens (JWTs). Specifically, Wings accepts any valid JWT containing `server_uuid`, `user_uuid`, and `unique_id`, irrespective of the token's intended purpose. This design flaw enables an authenticated subuser, even one with minimal permissions (e.g., only `websocket.connect`), to reuse a JWT issued for a lower-privilege operation (like WebSocket authentication or file downloads) to upload arbitrary files to the associated server. This bypasses the intended `file.create` permission checks, allowing unauthorized write access to the server's file system. This vulnerability affects anyone running vulnerable versions of the Pterodactyl game server management software.

## Attack Chain

1. An authenticated subuser gains minimal access to a Pterodactyl server, such as the ability to connect to the server's console (requiring `websocket.connect` permission).
2. The subuser makes an API request to a legitimate low-privilege endpoint on the Pterodactyl Panel, such as `/api/client/servers/[...]/websocket` or a file download endpoint, to obtain a panel-signed JSON Web Token (JWT).
3. The Pterodactyl Panel issues a JWT containing claims like `server_uuid`, `user_uuid`, and `unique_id`, which are used for various operations across the Panel and Wings.
4. The subuser intercepts and extracts this JWT.
5. The subuser then crafts an HTTP POST request to the Pterodactyl Wings `/upload/file` endpoint, including the obtained JWT as a query parameter (`?token=`).
6. The subuser includes arbitrary file content within the POST request, intending to upload it to the server.
7. The Pterodactyl Wings component, due to improper JWT scoping validation, accepts the JWT as valid for file upload, despite the token initially being issued for a different, lower-privilege action.
8. Wings proceeds to write the arbitrary file content to the server's file system, achieving unauthorized file upload and privilege escalation for the subuser.

## Impact

This vulnerability allows any authenticated subuser, regardless of their specific permissions on a server, to upload arbitrary files to that server. While the attacker must already have subuser access to the target server, this flaw significantly escalates their privileges beyond what is explicitly granted, potentially leading to unauthorized data modification, execution of malicious scripts, or further system compromise. The impact is confined to the specific server the subuser has access to; users without any subuser access cannot exploit this vulnerability. The inability to properly control file uploads can lead to data integrity issues, denial of service through disk exhaustion, or remote code execution if the uploaded files are executed by vulnerable services on the server.

## Recommendation

* **Patch CVE-2026-54593**: Upgrade Pterodactyl Panel to version 1.12.3 or newer, and Pterodactyl Wings to version 1.12.2 or newer immediately to mitigate CVE-2026-54593.
* **Deploy the Sigma rule**: Implement the provided Sigma rule in your SIEM to detect suspicious file upload attempts on the Pterodactyl Wings `/upload/file` endpoint. Tune this rule by identifying and allowlisting legitimate uses of this endpoint.
* **Enable webserver logging**: Ensure detailed webserver access logs are enabled for your Pterodactyl Wings instance to capture HTTP requests, including method, URI, query parameters, and status codes, which are crucial for detecting this activity.
