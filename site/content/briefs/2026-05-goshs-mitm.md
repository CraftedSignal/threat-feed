---
title: goshs SSH Tunnel Vulnerable to MITM via Insecure Host Key Handling
slug: 2026-05-goshs-mitm
description: The goshs application disables SSH host key verification when using the --tunnel flag, making it vulnerable to man-in-the-middle attacks that expose plaintext HTTP traffic.
date: "2026-05-15T17:19:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mitm
  - ssh
  - insecure-configuration
products:
  - goshs/v2 <= 2.0.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-mxg3-432p-mr72
rules:
  - title: Detect goshs SSH Connection to localhost.run with Tunnel Flag
    description: Detects goshs process initiating an SSH connection to localhost.run on port 22 when the --tunnel flag is present.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
  - title: Detect goshs SSH Connection to localhost.run with Tunnel Flag (Linux)
    description: Detects goshs process initiating an SSH connection to localhost.run on port 22 when the --tunnel flag is present.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The goshs application, prior to version 2.0.7, is vulnerable to a man-in-the-middle (MITM) attack when using the `--tunnel` or `-t` flag. The application opens an outbound SSH connection to `localhost.run:22` with host key verification disabled via `ssh.InsecureIgnoreHostKey()`. This insecure configuration allows an attacker positioned on the network path to intercept the TCP connection, present their own SSH host key, and proxy the connection. Because `localhost.run` performs TLS termination, the attacker can read and rewrite all HTTP request and response content in plaintext. This vulnerability allows for the exfiltration of sensitive data and modification of served content.

## Attack Chain

1. A user executes `goshs --tunnel` to create a tunnel.
2. `tunnel.Start()` initiates an SSH connection to `localhost.run:22` with `InsecureIgnoreHostKey()`.
3. An attacker, positioned on the network path, intercepts the TCP connection to `localhost.run:22` and responds with a malicious SSH server.
4. The malicious SSH server presents a fake SSH host key, which the goshs client accepts due to the disabled host key verification.
5. The attacker proxies the SSH session onward to the real `localhost.run:22` to retrieve the public URL.
6. All subsequent HTTP requests to the public URL are routed through the attacker's proxy.
7. The attacker intercepts all HTTP requests and responses, reading sensitive data such as URLs, headers, authentication credentials, and file contents.
8. The attacker can modify HTTP responses, inject malicious content, or redirect requests.

## Impact

The vulnerability can lead to significant data breaches and compromise of system integrity. All HTTP request and response content, including sensitive information such as URLs, headers, basic authentication credentials, file contents, and share-link tokens, can be read by the attacker. Furthermore, attackers can modify responses in transit, replacing served files, injecting malicious scripts, or substituting binaries with backdoored versions. This poses a high risk to both the confidentiality and integrity of the data being transmitted through the goshs tunnel.

## Recommendation

*   Upgrade to goshs version 2.0.7 or later to benefit from the fix that replaces `ssh.InsecureIgnoreHostKey()` with a TOFU host key verification mechanism.
*   Monitor network traffic for connections to `localhost.run:22` originating from goshs processes to detect potential MITM attempts, using the provided Sigma rule.
*   Regularly inspect the `~/.config/goshs/known_hosts` file to ensure the host key for `localhost.run:22` has not been tampered with (after upgrading).
