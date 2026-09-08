---
title: Information Disclosure Vulnerability in Netis NX10 Firmware
slug: 2026-09-netis-nx10-info-disclosure
description: Netis NX10 firmware versions V4.0.1.5808 and V3.0.0.4142 contain an information disclosure vulnerability allowing unauthenticated retrieval of administrator credentials via the web management interface.
date: "2026-09-08T15:41:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:netis:nx10_firmware:4.0.1.5808:*:*:*:*:*:*:*
  - cpe:2.3:o:netis:nx10_firmware:3.0.0.4142:*:*:*:*:*:*:*
vendors:
  - Netis
products:
  - NX10 (V4.0.1.5808, V3.0.0.4142)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can replay the exposed credential against the login handler to establish a fully authenticated administrator session on the device.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Attackers can replay the exposed credential against the login handler to establish a fully authenticated administrator session on the device.
    confidence_band: high
cves:
  - id: CVE-2026-61516
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61516
rules:
  - title: Detect CVE-2026-61516 Exploitation - Unauthorized Access to sysinfo
    description: Detects unauthenticated GET requests to the sysinfo endpoint on Netis NX10 web management interfaces, which may indicate exploitation attempts.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1110.001
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Netis NX10 devices and initiate firmware update to secure versions
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies affected versions V4.0.1.5808 and V3.0.0.4142
  mitigation_plan:
    - priority: immediate
      action: Restrict access to web management interface to trusted internal IP ranges
      owner: IT Operations
      addresses: CVE-2026-61516
      evidence: Vulnerability allows unauthenticated access to sysinfo action
---

Netis NX10 routers running firmware versions V4.0.1.5808 and V3.0.0.4142 are vulnerable to an unauthenticated information disclosure flaw. The vulnerability resides in the device's web management interface, specifically within the sysinfo action handler. By crafting a specific HTTP request, an unauthenticated attacker can bypass session validation checks and force the device to return sensitive information, including the administrative password in cleartext. This exposure provides attackers with full administrative control over the network device, which can be leveraged to modify firewall rules, intercept traffic, or pivot into the internal network environment. Given the potential for full device compromise and the lack of required authentication, this vulnerability represents a critical risk to infrastructure security.

## Impact

Successful exploitation allows for full administrative access to the targeted Netis NX10 router. This level of access facilitates persistent unauthorized control, traffic interception, configuration modification, and internal network reconnaissance. The vulnerability impacts residential and small office users deploying these specific firmware versions.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Identify and inventory all Netis NX10 devices across the network environment.
- Patch affected devices by upgrading to the latest manufacturer-recommended firmware version, as this vulnerability is exploitable without authentication.
- Restrict access to the web management interface of all networking hardware to trusted internal IP ranges only.
- Implement monitoring for abnormal HTTP GET requests targeting the '/sysinfo' endpoint in web management traffic logs.
- If a patch is unavailable, block access to the administrative web management interface from any untrusted or internet-facing network segments.
