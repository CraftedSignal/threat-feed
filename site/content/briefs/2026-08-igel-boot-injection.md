---
title: Boot Registry Parameter Injection in IGEL OS
slug: 2026-08-igel-boot-injection
description: CVE-2026-82017 allows attackers with physical access to inject arbitrary kernel command-line parameters into IGEL OS boot configurations, resulting in privilege escalation while bypassing TPM measurements.
date: "2026-08-28T23:35:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:igel:igel_os:12:*:*:*:*:*:*:*
  - cpe:2.3:o:igel:igel_os:11:*:*:*:*:*:*:*
vendors:
  - IGEL
products:
  - IGEL OS 12 (< 12.7.6)
  - IGEL OS 11 (< 11.11.150)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1542
    technique_name: Pre-OS Boot
    evidence: IGEL OS 12 before 12.7.6 and IGEL OS 11 before 11.11.150 contain a boot registry parameter injection vulnerability that allows attackers with physical access to execute arbitrary Linux loader parameters.
    confidence_band: high
cves:
  - id: CVE-2026-82017
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82017
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Infrastructure Security
  immediate_actions:
    - action: Upgrade IGEL OS 12 to 12.7.6 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to 12.7.6 or 11.11.150.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IGEL OS firmware to version 12.7.6 or 11.11.150.
      owner: IT Operations
      addresses: CVE-2026-82017
      evidence: Source advisory
---

CVE-2026-82017 is a boot-level vulnerability affecting IGEL OS 12 (versions prior to 12.7.6) and IGEL OS 11 (versions prior to 11.11.150). The flaw exists because the bootloader reads boot registry parameters from an unencrypted and unsigned configuration area. An attacker with physical access to the endpoint can modify these configuration files to inject arbitrary kernel command-line parameters. Because the attack targets the configuration data rather than the signed bootloader binary, the modifications do not trigger TPM PCR measurement failures, allowing the system to boot into a modified state with elevated privileges. This vulnerability is critical for organizations relying on IGEL OS endpoints for secure, locked-down kiosk or thin-client environments, as it effectively nullifies hardware-backed integrity protections.

## Attack Chain

1. Attacker gains physical access to the targeted IGEL OS endpoint.
2. Attacker initiates an interface to interact with the device storage (e.g., direct flash memory access or removable boot media manipulation).
3. Attacker identifies the unencrypted and unsigned configuration area used by the bootloader.
4. Attacker modifies the boot registry parameter files within this area to include malicious kernel command-line parameters.
5. Attacker reboots or performs a hard reset on the target endpoint.
6. The system bootloader executes, reading the tampered configuration parameters into the kernel startup sequence.
7. The kernel initializes with the injected parameters, executing with boot environment privileges.
8. Attacker gains persistence or full control over the OS environment while bypassing established TPM security measurements.

## Impact

Successful exploitation allows for the compromise of endpoint integrity, bypassing boot-time security controls such as TPM-based measured boot. This could facilitate the deployment of rootkits, exfiltration of stored credentials, or the total bypass of endpoint configuration locks in enterprise, healthcare, or financial kiosk environments.

## Recommendation

Prioritized, concrete actions for engineering teams:
- Upgrade all IGEL OS 12 endpoints to version 12.7.6 or later immediately.
- Upgrade all IGEL OS 11 endpoints to version 11.11.150 or later immediately.
- Apply physical security controls to IGEL OS endpoints to prevent unauthorized access to storage media or boot interfaces.
