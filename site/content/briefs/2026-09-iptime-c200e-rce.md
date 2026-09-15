---
title: Remote Code Execution in EFM ipTIME C200E via Command Injection
slug: 2026-09-iptime-c200e-rce
description: An unauthenticated remote command injection vulnerability in EFM ipTIME C200E firmware version 1.094 allows remote attackers to execute arbitrary operating system commands via the iux_set.cgi script.
date: "2026-09-15T01:37:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:efm:iptime_c200e_firmware:1.094:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve-2026-90847
  - networking
  - command-injection
vendors:
  - EFM
products:
  - ipTIME C200E (1.094)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This manipulation causes os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-90847
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90847
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all EFM ipTIME C200E devices and restrict exposure of web management interface to untrusted networks.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90847 critical severity rating.
  mitigation_plan:
    - priority: immediate
      action: Identify and apply firmware patches from EFM as they become available for CVE-2026-90847.
      owner: IT Operations
      addresses: CVE-2026-90847
      evidence: NVD disclosure of command injection vulnerability.
---

EFM ipTIME C200E firmware version 1.094 is vulnerable to an OS command injection flaw located within the iux_set.cgi file of the System Setup component. This vulnerability stems from improper input validation when handling requests sent to the CGI interface. An unauthenticated, remote attacker can exploit this weakness by crafting malicious HTTP requests to the target device. Successful exploitation allows for the execution of arbitrary commands with the privileges of the web service process, which typically runs with elevated permissions on embedded networking devices. Given the public disclosure of a functional exploit, organizations utilizing these devices face an immediate risk of compromise, including potential device hijacking, unauthorized data access, or integration into botnets.

## Impact

Successful exploitation of CVE-2026-90847 grants an attacker remote code execution capabilities on the affected ipTIME C200E devices. This can lead to a total loss of confidentiality, integrity, and availability of the device, potentially facilitating lateral movement into the local network where the device is deployed. As the vulnerability is remotely exploitable without authentication, any internet-exposed device is at high risk of automated exploitation by threat actors scanning for vulnerable networking equipment.

## Recommendation

Identify and inventory all EFM ipTIME C200E devices deployed within the environment. If possible, restrict administrative access and the iux_set.cgi interface to trusted internal management subnets. Monitor web server logs for HTTP requests directed at iux_set.cgi containing shell metacharacters such as semicolon, pipe, or backticks that suggest command injection attempts. Contact the vendor for firmware updates addressing CVE-2026-90847.
