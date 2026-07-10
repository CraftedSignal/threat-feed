---
title: Incus WebUI Authentication Bypass Vulnerability (CVE-2026-33898)
slug: 2024-01-incus-auth-bypass
description: Incus versions prior to 6.23.0 are vulnerable to an authentication bypass in the `incus webui` component, allowing local attackers to gain elevated privileges or remote attackers to access system resources by exploiting the incorrect validation of authentication tokens.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-33898
  - privilege-escalation
  - authentication-bypass
  - linux
vendors:
  - Incus
products:
  - Incus
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33898
rules:
  - title: Detect Network Connection to Incus WebUI Server
    description: Detects network connections to the Incus WebUI server on localhost, which could indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
  - title: Detect Incus WebUI Process Creation
    description: Detects the creation of the incus webui process, which should be monitored closely due to the authentication bypass vulnerability.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect HTTP requests to Incus WebUI with tokens
    description: Detects HTTP requests to the Incus WebUI containing tokens in the URI, which is unusual after the initial authentication.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Incus is a system container and virtual machine manager. Prior to version 6.23.0, the `incus webui` component contains an authentication bypass vulnerability (CVE-2026-33898). The vulnerability lies in the incorrect validation of authentication tokens by the web server spawned by `incus webui`. `incus webui` launches a local web server on a randomly assigned localhost port and issues a URL containing an authentication token for user access. While the Incus client correctly validates cookies, it fails to properly validate tokens passed directly in the URL. This flaw can be exploited by an attacker able to communicate with the temporary web server on localhost. Successful exploitation grants the attacker the same privileges as the user who initiated `incus webui`. This impacts system security as it may lead to privilege escalation or unauthorized access to Incus instances and potentially system resources. The vulnerability is resolved in Incus version 6.23.0.

## Attack Chain

1. A user initiates the `incus webui` command, which spawns a temporary web server on a random localhost port (e.g., 127.0.0.1:8080).
2. Incus provides the user with a URL containing an authentication token (e.g., http://127.0.0.1:8080/?token=abcdef123456).
3. An attacker gains access to the network or system where the Incus webui is running, and identifies the localhost port being used.
4. The attacker crafts a malicious request to the `incus webui` web server, using a valid or even an invalid token in the URL. The vulnerability does not properly validate the token.
5. Due to the authentication bypass, the attacker is granted access to the Incus webui with the privileges of the user who started the `incus webui` instance.
6. If the attacker is a local user, they can leverage their newly acquired privileges to escalate their access to the system.
7. The attacker could manipulate Incus instances, access sensitive data, or potentially gain control of underlying system resources.
8. The attacker achieves privilege escalation or unauthorized access, depending on the attacker's initial location and goals.

## Impact

Successful exploitation of CVE-2026-33898 allows an attacker to gain the privileges of the user running `incus webui`. If the attacker is a local user, this results in privilege escalation, allowing them to perform actions they were previously unauthorized to do. A remote attacker who can trick a local user into interacting with the Incus web UI server could gain unauthorized access to Incus instances and potentially sensitive system resources. The CVSS v3.1 base score for this vulnerability is 8.8, indicating a high severity.

## Recommendation

*   Upgrade Incus to version 6.23.0 or later to patch the vulnerability (CVE-2026-33898).
*   Implement network segmentation to restrict access to the `incus webui` web server.
*   Monitor network connections to the `incus webui` web server for suspicious activity (see the network connection Sigma rule below).
*   Audit the use of `incus webui` in your environment and restrict its use to authorized personnel only.
