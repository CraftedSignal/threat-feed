---
title: Remote Command Injection in RedPort Optimizer wXa Series
slug: 2026-09-redport-command-injection
description: RedPort Optimizer wXa-203, wXa-213, and wXa-223 devices running firmware up to 20260704 are vulnerable to unauthenticated remote code execution due to command injection in the System Clock component.
date: "2026-09-01T01:01:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:redport:optimizer_wxa-203:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redport:optimizer_wxa-213:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redport:optimizer_wxa-223:*:*:*:*:*:*:*:*
vendors:
  - RedPort
products:
  - Optimizer wXa-203 (<= 20260704)
  - Optimizer wXa-213 (<= 20260704)
  - Optimizer wXa-223 (<= 20260704)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation leads to command injection.
    confidence_band: high
cves:
  - id: CVE-2026-83524
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83524
rules:
  - title: Detects CVE-2026-83524 Exploitation - Unauthenticated RCE via datetime.php
    description: Detects exploitation attempts against CVE-2026-83524 targeting the system clock component with shell metacharacters in the query string
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to RedPort Optimizer management interface
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated remote exploit is publicly available
  hunt_leads:
    - lead: Search logs for requests to /xgatev1/system/datetime.php
      technique_id: T1203
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows command injection via this specific URI
  mitigation_plan:
    - priority: immediate
      action: Network segmentation and access restriction
      owner: IT Operations
      addresses: CVE-2026-83524
      evidence: Exploit is public and vendor has not responded
---

A critical vulnerability (CVE-2026-83524) exists in the RedPort Optimizer wXa series, specifically models wXa-203, wXa-213, and wXa-223 running firmware versions up to 20260704. The flaw resides within the System Clock component, specifically inside the 'exec' function located in '/xgatev1/system/datetime.php'. An unauthenticated remote attacker can supply malicious input to this endpoint to achieve command injection. Because the exploitation of this vulnerability has been disclosed publicly, the risk of exploitation by opportunistic threat actors is significantly elevated. Despite notification, the vendor has not provided a response or a patch to remediate this issue, leaving deployed devices exposed to remote exploitation. Defenders should monitor for unexpected HTTP POST or GET requests to the specified URI on these network-attached devices.

## Impact

Successful exploitation of this vulnerability leads to unauthenticated remote code execution on the affected RedPort Optimizer network devices. This allows attackers to fully compromise the device, potentially facilitating lateral movement within the network, interception of satellite communication traffic routed through the Optimizer, or persistent access to the network edge. Given the nature of these devices as satellite gateways, a compromise could have severe operational consequences for maritime and remote-site connectivity.

## Recommendation

1. Restrict administrative access to the RedPort Optimizer management interface to trusted IP ranges only.
2. Implement network egress filtering for these devices to prevent them from reaching unknown command-and-control infrastructure.
3. Monitor web server logs for HTTP requests targeting '/xgatev1/system/datetime.php' containing suspicious parameters, such as shell metacharacters (e.g., ;, |, &, $, `).
4. Segment these devices into an isolated VLAN to minimize the impact if they are compromised.
