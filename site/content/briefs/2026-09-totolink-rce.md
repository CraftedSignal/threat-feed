---
title: Remote Code Execution in TOTOLINK N150RT
slug: 2026-09-totolink-rce
description: An OS command injection vulnerability in the TOTOLINK N150RT web interface allows unauthenticated remote attackers to execute arbitrary commands via the wlanif parameter.
date: "2026-09-28T03:11:42Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:totolink:n150rt:*:*:*:*:*:*:*:*
tags:
  - cve-2026-100896
  - command-injection
  - remote-code-execution
  - network-appliance
vendors:
  - TOTOLINK
products:
  - N150RT (3.4.0-B20201030)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-100896
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100896
rules:
  - title: Detect CVE-2026-100896 Exploitation - OS Command Injection in TOTOLINK
    description: Detects exploitation of CVE-2026-100896 by monitoring for malicious shell metacharacters within the wlanif parameter of the formWlSiteSurvey handler.
    platform: sigma
    severity: critical
    tactics:
      - execution
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
    - Network Security
  immediate_actions:
    - action: Block external access to TOTOLINK web interfaces
      owner: Network Security
      due: 24h
      evidence: Publicly available exploit code exists, posing a high risk
  mitigation_plan:
    - priority: immediate
      action: Disable remote management features on affected TOTOLINK devices
      owner: IT Operations
      addresses: CVE-2026-100896
      evidence: Exploit targets Web Management Interface
---

TOTOLINK N150RT firmware version 3.4.0-B20201030 contains a critical command injection vulnerability (CVE-2026-100896) within its Web Management Interface. The flaw is located in the '/boafrm/formWlSiteSurvey' handler, which improperly sanitizes user-supplied input provided to the 'wlanif' argument. An unauthenticated remote attacker can leverage this vulnerability to inject and execute arbitrary system-level commands on the underlying device. Given that public exploit code is already available, the risk of active exploitation by threat actors is high. Defenders should ensure these devices are isolated from the public internet and monitored for suspicious HTTP POST requests directed at the identified handler.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible TOTOLINK N150RT web management interfaces.
2. Attacker initiates an HTTP POST request to the target device endpoint: /boafrm/formWlSiteSurvey.
3. Attacker crafts a malicious payload containing shell metacharacters (e.g., ;, |, &&) within the 'wlanif' parameter.
4. The web server process parses the HTTP request and passes the tainted 'wlanif' argument to a system-level function call.
5. The underlying OS executes the injected command with the privileges of the web management service.
6. The attacker establishes a reverse shell or downloads secondary payloads to achieve persistent unauthorized access.

## Impact

Successful exploitation allows for full system compromise, including unauthorized code execution, potential exfiltration of sensitive configuration data, and the ability to repurpose the device for further malicious activities within the local network. 

## Recommendation

1. Immediately restrict access to the Web Management Interface of TOTOLINK devices from the public internet.
2. Implement network-level monitoring to detect POST requests to '/boafrm/formWlSiteSurvey' containing shell metacharacters in the query parameters.
3. Update firmware to the latest available version if a patch is provided by the manufacturer, as version 3.4.0-B20201030 is confirmed vulnerable.
