---
title: Nginx-UI Unauthenticated Bootstrap Takeover
slug: 2024-01-nginx-ui-takeover
description: Nginx-UI version 2.3.5 is vulnerable to an unauthenticated takeover via the `/api/install` endpoint during the initial setup window, allowing a remote attacker to claim administrative control of a fresh instance.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - nginx-ui
  - bootstrap-takeover
  - unauthenticated-access
  - initial-access
vendors:
  - nginx-ui
products:
  - nginx-ui (2.3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-mxqh-q9h6-v8pq
iocs:
  - type: url
    value: http://127.0.0.1:9000/api/install
ioc_counts:
  url: 1
rules:
  - title: Detect Nginx-UI Initial Setup Takeover Attempt
    description: Detects POST requests to /api/install with encrypted parameters, indicating a potential unauthenticated takeover attempt during the initial setup phase.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Nginx-UI Login with Recently Created User
    description: Detects logins shortly after a POST request to /api/install, potentially indicating the attacker is logging in with the newly created account.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Nginx-UI version 2.3.5 contains a critical vulnerability that allows unauthenticated remote attackers to take complete administrative control of a fresh instance. The vulnerability lies in the `/api/install` endpoint, which is accessible without authentication during a short initial setup window. This window is intended for the first-time configuration of the application. By sending a specially crafted POST request to `/api/install`, an attacker can set the application's JWT secret, node secret, certificate email, and initial administrator credentials before the legitimate operator. This attack is most relevant during initial deployments, rebuilds, ephemeral test environments, LAN-accessible fresh installs, or temporarily exposed setup workflows. The attacker gains full control without needing to exploit any authenticated feature or guess default credentials. The observed exploitation was reproduced over HTTP against live local instances started from `nginx-ui` `v2.3.5` using Docker image `uozi/nginx-ui@sha256:d73343e3009c9b558129a2be0cacd6c2c57ed8006a5871873b874b812e612e5a`.

## Attack Chain

1. A fresh `nginx-ui` instance is deployed, exposing the `/api/install` endpoint over HTTP before initial configuration.
2. The attacker sends a GET request to `/api/install` to determine if the instance is uninitialized (checks for `{"lock":false,"timeout":false}`).
3. The attacker sends a GET request to `/api/crypto/public_key` to retrieve the public key used for encryption.
4. The attacker uses the retrieved public key to encrypt a JSON payload containing the desired administrator username, password, and email.
5. The attacker sends a POST request to `/api/install` with the encrypted payload in the `encrypted_params` field.
6. The server processes the request, sets the attacker-chosen credentials, and locks the installation (`{"lock":true,"timeout":false}`).
7. The attacker sends a POST request to `/api/login` with the attacker-chosen username and password, also encrypted with the previously obtained public key.
8. The server authenticates the attacker and returns a valid token, granting them administrative access to the `nginx-ui` instance.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to completely compromise a fresh `nginx-ui` instance. The attacker gains full administrative privileges and can configure the application, manage Nginx configurations, and potentially use the compromised server as a pivot point for further attacks. The exposure window is limited to the initial setup phase, but if successfully exploited, the attacker effectively becomes the administrator of the system.

## Recommendation

*   Monitor web server logs for POST requests to `/api/install` with a non-empty `encrypted_params` field, especially from unusual source IP addresses, to detect potential takeover attempts. Deploy the Sigma rule `Detect Nginx-UI Initial Setup Takeover Attempt` to your SIEM.
*   Restrict access to the `/api/install` endpoint to localhost or trusted networks during the initial setup phase using firewall rules or web server configuration.
*   Apply the suggested fixes from the advisory, including requiring a local-only or out-of-band bootstrap secret for `POST /api/install`, to prevent unauthorized installation claims.
*   Monitor for unexpected processes creating files or directories under `/etc/nginx` or `/etc/nginx-ui` immediately after a new deployment of `nginx-ui` to identify potential persistence attempts.
