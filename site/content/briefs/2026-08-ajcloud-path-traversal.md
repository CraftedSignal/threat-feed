---
title: Path Traversal Vulnerability in AJCloud AJY IPC Firmware
slug: 2026-08-ajcloud-path-traversal
description: A path traversal vulnerability in the AJCloud AJY IPC jdbhttpd web service allows unauthenticated remote attackers to read arbitrary files with root privileges via crafted URI requests.
date: "2026-08-30T23:12:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:ajcloud:ajy_ipc_firmware:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - iiot
  - cve-2026-56718
vendors:
  - AJCloud
products:
  - AJY IPC firmware (< 01.10715.11.37)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can exploit this via crafted HTTP requests on port 80 to access arbitrary files with root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-56718
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56718
rules:
  - title: Detects CVE-2026-56718 Exploitation - Path Traversal in AJCloud jdbhttpd
    description: Detects attempts to exploit CVE-2026-56718 by identifying path traversal sequences (../) in HTTP requests targeting AJCloud IPC devices
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade AJY IPC firmware to 01.10715.11.37 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states firmware prior to 01.10715.11.37 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to port 80 on AJCloud devices via firewall ACLs.
      owner: IT Operations
      addresses: CVE-2026-56718
      evidence: Exploitation occurs over port 80 via unauthenticated requests.
---

AJCloud AJY IPC firmware versions prior to 01.10715.11.37 contain a path traversal vulnerability in the jdbhttpd web service. This flaw enables unauthenticated remote attackers to bypass access controls and read arbitrary files on the underlying file system with root privileges. By injecting path traversal sequences into HTTP requests directed at port 80, an adversary can retrieve sensitive system files. The exposure includes credentials for RTSP streams, Wi-Fi network SSID and pre-shared keys, device serial numbers, and cloud binding parameters. This vulnerability represents a significant risk for the confidentiality of device configurations and network access credentials, potentially facilitating lateral movement or further exploitation within the connected environment.

## Impact

Successful exploitation allows for the unauthorized extraction of sensitive configuration data, including Wi-Fi security keys and RTSP credentials. These data points provide an attacker with the ability to gain network access or intercept video streams from the affected cameras. The scope of targeting includes all deployments of AJY IPC devices running firmware versions earlier than 01.10715.11.37.

## Recommendation

Update the firmware for all AJCloud AJY IPC devices to version 01.10715.11.37 or later immediately to address CVE-2026-56718. For environments where patching cannot occur immediately, restrict access to the web management interface on port 80 to trusted management subnets using network segmentation or firewall ACLs.
