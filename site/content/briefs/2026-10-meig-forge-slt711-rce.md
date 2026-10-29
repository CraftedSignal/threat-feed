---
brief_id: brief-2026-10-29-meig-forge-slt711-rce
event_id: brief-2026-10-29-meig-forge-slt711-rce
revision: 1
activity_at: "2026-10-29T18:04:07Z"
title: 'MeiG Smart FORGE_SLT711: Unauthenticated OS command injection (CVE-2026-36356)'
slug: 2026-10-meig-forge-slt711-rce
description: An unauthenticated OS command injection vulnerability in the MeiG Smart FORGE_SLT711 router allows remote attackers to execute arbitrary commands as root via the /action/SetRemoteAccessCfg endpoint.
date: "2026-10-29T18:04:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for production.
cpes:
  - cpe:2.3:a:meig_smart_technology:forge_slt711:*:*:*:*:*:*:*:*
tags:
  - cve-2026-36356
  - rce
  - command-injection
  - network-device
vendors:
  - MeiG Smart Technology
products:
  - FORGE_SLT711 (firmware MDM9607.LE.1.0-00110-STD.PROD-1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GoAhead web server bundled with MeiG Smart FORGE_SLT711 4G LTE CPE devices exposes an unauthenticated HTTP endpoint, /action/SetRemoteAccessCfg.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: The password field is interpolated inside double quotes. $(...) substitution and `...` backticks expand inside double quotes, so an attacker controls the shell command.
    confidence_band: high
cves:
  - id: CVE-2026-36356
    cvss: 9.1
    epss: 0.20348
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TOTEKUH-CVE-2026-36356
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TOTEKUH-CVE-2026-36356&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-36356 Exploitation - Unauthenticated RCE via SetRemoteAccessCfg
    description: Detects exploitation attempts against CVE-2026-36356 by identifying HTTP POST requests to the /action/SetRemoteAccessCfg endpoint containing shell metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Configure WAF or ingress firewall rules to block traffic to /action/SetRemoteAccessCfg from untrusted networks.
      owner: SOC
      due: 24h
      evidence: Unauthenticated RCE via /action/SetRemoteAccessCfg
  hunt_leads:
    - lead: Hunt for inbound POST requests to /action/SetRemoteAccessCfg.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The GoAhead web server... exposes an unauthenticated HTTP endpoint, /action/SetRemoteAccessCfg
  mitigation_plan:
    - priority: immediate
      action: Disable remote access to the management interface on all affected FORGE_SLT711 devices.
      owner: IT Operations
      addresses: CVE-2026-36356
      evidence: A single unauthenticated POST request executes arbitrary commands as root.
---

CVE-2026-36356 is a critical vulnerability in the MeiG Smart FORGE_SLT711 4G LTE CPE router. The custom action handler for the GoAhead web server, specifically the '/action/SetRemoteAccessCfg' endpoint, fails to perform authentication and does not sanitize the 'password' parameter provided in JSON POST requests. This allows an unauthenticated attacker to inject shell commands into a 'system()' call executed with root privileges. Public exploit code is available.

## Impact
Successful exploitation allows remote, unauthenticated attackers to gain a full root shell on affected CPE devices. The vulnerability facilitates persistent access, such as the deployment of a telnet backdoor, and full system control.

## Recommendation
- Identify all internet-facing MeiG Smart FORGE_SLT711 devices.
- Restrict access to the router's web management interface to trusted internal IP ranges or VPN-only access.
- Coordinate with the vendor or service provider to verify if a firmware patch is available to address the unsafe 'sprintf' and 'system' implementation in the GoAhead handler.
- Deploy detection rules to monitor for suspicious HTTP POST requests directed at the '/action/SetRemoteAccessCfg' endpoint.
