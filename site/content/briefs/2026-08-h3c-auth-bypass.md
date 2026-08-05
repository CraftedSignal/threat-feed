---
title: Unauthenticated Access Vulnerability in H3C NX15
slug: 2026-08-h3c-auth-bypass
description: A missing authentication vulnerability in the H3C NX15 network device firmware (CVE-2026-18810) allows unauthenticated remote attackers to access the /api/wizard/networkSetup endpoint, potentially enabling unauthorized configuration changes.
date: "2026-08-04T22:02:27Z"
lastmod: "2026-08-05T06:05:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-18812
  - command-injection
  - network-device
  - cve-2026-18813
  - rce
vendors:
  - H3C
products:
  - NX15 (V100R017)
  - NX15
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security vulnerability has been detected in H3C NX15 V100R017. Impacted is an unknown function of the file /api/wizard/networkSetup. Such manipulation leads to missing authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Performing a manipulation of the argument esps.filter.url results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-18810
    cvss: 7.3
  - id: CVE-2026-18814
    cvss: 7.2
  - id: CVE-2026-18811
    cvss: 7.2
  - id: CVE-2026-18812
    cvss: 7.2
  - id: CVE-2026-18900
    cvss: 7.2
  - id: CVE-2026-18813
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18810
  - https://vuldb.com/cve/CVE-2026-18810
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/api_wizard_networksetup_preauth_hijack
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18811
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/esps_filter_url_add_root_rce
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18812
  - https://vuldb.com/vuln/385811
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18813
  - https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/esps_apcm_version_delete_root_rce
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18814
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18900
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18901
iocs:
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/tree/main/H3C/NX15R017/service_add_root_rce
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/blob/main/H3C/NX15R017/file_exec_root_rce/poc/postauth_file_exec_rce.py
  - type: url
    value: https://github.com/coconut652-7/IOT_Vul_Public/blob/main/H3C/NX15R017/service_add_root_rce_chain/poc/postauth_service_add_rce.py
ioc_counts:
  url: 3
rules:
  - title: Detects CVE-2026-18810 Exploitation - Unauthenticated Access to Network Setup
    description: Detects unauthenticated HTTP requests to the /api/wizard/networkSetup endpoint associated with CVE-2026-18810 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-18811 Exploitation Attempt
    description: Detects exploitation attempts against H3C NX15 devices targeting the /api/esps endpoint by looking for shell metacharacters in the esps.filter.url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-18812 Exploitation - Command Injection in H3C NX15
    description: Detects attempts to exploit CVE-2026-18812 by identifying shell metacharacters in the workMode argument of the /api/esps endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-18813 Exploitation - Command Injection in H3C NX15
    description: Detects attempted exploitation of CVE-2026-18813 by monitoring HTTP requests to the /api/esps endpoint containing shell metacharacters in the esps.apcm.version parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to the management interface of H3C NX15 devices
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18810 documentation identifies the vulnerability as remotely exploitable
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches for CVE-2026-18810
      owner: IT Operations
      addresses: CVE-2026-18810
      evidence: Vulnerability requires firmware update or configuration change
updates:
  - at: "2026-08-04T22:02:47Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-18812 Exploitation - Command Injection in H3C NX15'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18812
  - at: "2026-08-04T22:02:57Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-18813 Exploitation - Command Injection in H3C NX15'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18813
  - at: "2026-08-05T00:02:55Z"
    level: L2
    summary: added CVE-2026-18811 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18814
  - at: "2026-08-05T06:05:02Z"
    level: L2
    summary: added CVE-2026-18813, CVE-2026-18900
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18900
      - https://nvd.nist.gov/vuln/detail/CVE-2026-18901
---

A security vulnerability identified as CVE-2026-18810 affects H3C NX15 devices running firmware version V100R017. The vulnerability exists within the /api/wizard/networkSetup endpoint, where improper authentication handling allows remote, unauthenticated actors to interact with the device. This flaw is classified as CWE-306 (Missing Authentication for Critical Function), meaning the device fails to verify the identity of the requester before allowing access to administrative or setup functionalities. Successful exploitation can allow an attacker to bypass intended security controls and potentially reconfigure the network device remotely. This vulnerability is significant as it affects the management plane of network infrastructure equipment, providing a vector for persistent unauthorized access or further network-level exploitation if the device is internet-facing.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to reach sensitive API endpoints on H3C NX15 devices. If exploited, an attacker could alter network settings, change administrative credentials, or manipulate traffic routing policies, leading to full device compromise. Given the function of the affected API relates to network setup, the impact is high, particularly for devices deployed at the edge of corporate or branch office networks where they provide critical connectivity.

## Recommendation

Prioritized actions for security and IT teams include:
- Audit all internet-facing H3C NX15 devices and restrict access to the web management interface to known, trusted management subnets or via a VPN.
- Monitor logs for unauthorized access patterns directed at the /api/wizard/networkSetup endpoint.
- Verify device firmware versions and coordinate with H3C support to apply patches or mitigations to address CVE-2026-18810.
