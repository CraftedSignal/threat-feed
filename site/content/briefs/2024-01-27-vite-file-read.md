---
title: Vite Arbitrary File Read Vulnerability via WebSocket
slug: 2024-01-27-vite-file-read
description: Vite versions 6.0.0 to 8.0.4 are vulnerable to arbitrary file read, allowing attackers to bypass access controls and retrieve the contents of arbitrary files on the server via the WebSocket path when the dev server is exposed to the network.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vite
  - file-read
  - vulnerability
  - websocket
vendors:
  - Vite
products:
  - Vite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-p9ff-h696-f583
rules:
  - title: Vite WebSocket Connection Without Origin
    description: Detects WebSocket connections to a Vite development server without an Origin header, which is a prerequisite for exploiting the arbitrary file read vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Vite Dev Server Exposed to Network
    description: Detects Vite dev server running with host option exposed to the network.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Vite, a popular build tool, is susceptible to an arbitrary file read vulnerability affecting versions 6.0.0 through 8.0.4. This vulnerability arises when the Vite development server is exposed to the network using the `--host` command-line argument or the `server.host` configuration option, and the WebSocket is not disabled (`server.ws: false`). An attacker can exploit this by sending a `vite:invoke` request via the WebSocket to the `fetchModule` method, bypassing the `server.fs` access controls enforced on HTTP requests. This allows an unauthenticated attacker to retrieve the content of any file on the server, including sensitive configuration files and source code, which could lead to information disclosure and further exploitation. The vulnerability was reported on April 6th, 2026.

## Attack Chain

1.  The attacker identifies a vulnerable Vite development server exposed to the network (e.g., via Shodan or similar reconnaissance).
2.  The attacker connects to the Vite dev server's WebSocket without an `Origin` header.
3.  The attacker sends a crafted `vite:invoke` WebSocket message to call the `fetchModule` method.
4.  The `vite:invoke` message includes a `file://` URL pointing to the target file (e.g., `/etc/passwd`) along with the `?raw` query parameter.
5.  The vulnerable Vite server processes the `fetchModule` request through the WebSocket connection, bypassing the intended HTTP access controls.
6.  The server reads the contents of the specified file.
7.  The server returns the file contents as a JavaScript string within a WebSocket response.
8.  The attacker receives the file content and can use it to gather sensitive information.

## Impact

Successful exploitation allows an attacker to read arbitrary files on the server where the Vite development server is running. This includes development machines, CI environments, and containers. The vulnerability can lead to the disclosure of sensitive information, such as application source code, configuration files containing credentials, and internal documentation. This could allow an attacker to gain unauthorized access to internal systems and data, leading to potential data breaches or further compromise of the environment.

## Recommendation

*   Upgrade Vite to a patched version (>= 8.0.5, >= 7.3.2, >= 6.4.2) to remediate the vulnerability.
*   Ensure that the Vite development server is not exposed to the public network unless absolutely necessary. If exposure is required, implement strict network access controls.
*   Disable the WebSocket server (`server.ws: false`) if it is not required for development purposes.
*   Monitor network connections for unusual WebSocket activity originating from or directed towards Vite development servers. Deploy the following Sigma rule to detect WebSocket connections without an Origin header: `Vite WebSocket Connection Without Origin`
*   Review and restrict the `server.fs.allow` configuration to limit file system access, even though it is bypassed in this vulnerability.
