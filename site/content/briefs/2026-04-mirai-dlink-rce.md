---
title: Mirai Campaign Exploiting CVE-2025-29635 in D-Link Routers
slug: 2026-04-mirai-dlink-rce
description: A new Mirai-based malware campaign is exploiting CVE-2025-29635, a command-injection vulnerability affecting D-Link DIR-823X routers, to enlist devices into the botnet.
date: "2026-04-23T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - mirai
  - ddos
  - rce
  - iot
vendors:
  - D-Link
  - TP-Link
  - ZTE
products:
  - DIR-823X
  - ZXV10 H108L
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583.001
    technique_name: 'Acquire Infrastructure: Domains'
cves:
  - id: CVE-2025-29635
    cvss: 8.8
    epss: 0.69694
  - id: CVE-2023-1389
    cvss: 8.8
    epss: 0.93543
references:
  - https://www.bleepingcomputer.com/news/security/new-mirai-campaign-exploits-rce-flaw-in-eol-d-link-routers/
rules:
  - title: Detect Mirai dlink.sh Download
    description: Detects HTTP requests attempting to download the dlink.sh script associated with the Mirai campaign exploiting CVE-2025-29635.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - webserver
      - linux
  - title: Detect POST Request to D-Link Configuration Endpoint
    description: Detects POST requests to the /goform/set_prohibiting endpoint, which is targeted by CVE-2025-29635 exploits.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A new Mirai-based malware campaign has been observed exploiting CVE-2025-29635, a high-severity command injection vulnerability affecting D-Link DIR-823X routers. Discovered by Akamai's SIRT in March 2026, the campaign involves attackers sending malicious POST requests to vulnerable D-Link routers to execute arbitrary commands. This vulnerability allows attackers to download and execute a shell script, ultimately leading to the deployment of Mirai-based malware. The affected D-Link routers reached end-of-life in November 2024, meaning a patch is unlikely. The same actor is also exploiting CVE-2023-1389 impacting TP-Link routers, and an RCE flaw in ZTE ZXV10 H108L routers, deploying the same Mirai payload.

## Attack Chain

1. The attacker sends a POST request to the `/goform/set_prohibiting` endpoint on the D-Link DIR-823X router.
2. The POST request exploits CVE-2025-29635 to inject and execute arbitrary commands.
3. The injected commands change directories across writable paths on the router.
4. A shell script named `dlink.sh` is downloaded from an external IP address.
5. The `dlink.sh` script is executed on the compromised router.
6. The script installs a Mirai-based malware variant named "tuxnokill".
7. "tuxnokill" establishes persistence and begins scanning for new targets.
8. The compromised device is then used to launch DDoS attacks, leveraging Mirai's standard capabilities, including TCP SYN/ACK/STOMP, UDP floods, and HTTP null attacks.

## Impact

Successful exploitation of CVE-2025-29635 allows attackers to remotely execute arbitrary commands on vulnerable D-Link DIR-823X routers. The compromised routers are then incorporated into the Mirai botnet, increasing its size and DDoS capabilities. Given that these routers are end-of-life, many remain unpatched, potentially leading to a large number of compromised devices. This can result in network disruptions and service outages for targeted entities, as well as potential data exfiltration.

## Recommendation

*   Monitor network traffic for POST requests to the `/goform/set_prohibiting` endpoint on D-Link routers, as described in the Attack Chain, to detect potential exploitation attempts.
*   Deploy the Sigma rule `Detect Mirai dlink.sh Download` to identify attempts to download the malicious shell script.
*   If using affected D-Link DIR-823X routers, TP-Link, or ZTE ZXV10 H108L routers, upgrade to a supported device or implement network segmentation to limit potential damage.
*   Block the external IP address hosting the `dlink.sh` script if it can be reliably determined and is observed on your network.
