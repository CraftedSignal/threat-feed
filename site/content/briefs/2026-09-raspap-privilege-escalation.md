---
title: Privilege Management Vulnerability in RaspAP raspap-webgui
slug: 2026-09-raspap-privilege-escalation
description: An improper privilege management vulnerability in RaspAP raspap-webgui allows remote attackers to manipulate sudo configuration files, potentially leading to unauthorized privilege escalation.
date: "2026-09-29T02:24:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:raspap:raspap-webgui:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
vendors:
  - RaspAP
products:
  - raspap-webgui (<= 3.5.5)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Performing a manipulation results in improper privilege management.
    confidence_band: high
cves:
  - id: CVE-2026-101860
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101860
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the web interface via firewall
      owner: IT Operations
      due: 24h
      evidence: Remote exploitation potential
  mitigation_plan:
    - priority: immediate
      action: Monitor /etc/sudoers for unauthorized modifications
      owner: SOC
      addresses: CVE-2026-101860
      evidence: Source document identifies sudo configuration as the target component
---

A security vulnerability exists in RaspAP raspap-webgui versions 3.5.5 and earlier. The flaw resides within the PluginInstaller::addSudoers function located in 'src/RaspAP/Plugins/PluginInstaller.php'. The component responsible for sudo configuration management fails to properly sanitize or restrict inputs, allowing an attacker to perform unauthorized manipulations of the sudoers file. This vulnerability is classified as improper privilege management and can be initiated remotely. Publicly available exploit code exists, increasing the risk for internet-exposed instances of the web interface. Because the vendor has not responded to disclosure attempts, no official patch is available to remediate the vulnerability at this time. Defenders should isolate affected web interfaces or implement strict access controls to prevent unauthorized remote exploitation.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to gain elevated privileges on the underlying host system. By manipulating the sudoers file, an attacker can grant themselves or other users unrestricted root execution permissions. This impact is significant given that RaspAP is typically used to manage networking hardware, and compromise would provide full control over the router or gateway functionality.

## Recommendation

* Restrict network access to the raspap-webgui interface to trusted management subnets using network-level firewalls.
* Monitor the integrity of the /etc/sudoers file for unauthorized modifications.
* Audit the raspap-webgui process for unexpected child processes or unusual shell spawns.
* Disable the web-based sudo configuration component if it is not strictly required for environment operations.
