---
title: HKUDS OpenHarness Insecure Default Configuration Vulnerability
slug: 2026-04-openharness-default-config
description: 'HKUDS OpenHarness prior to PR #147 remediation contains an insecure default configuration vulnerability where remote channels inherit permissive access, potentially leading to unauthorized file disclosure and read access.'
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - insecure-configuration
  - access-control
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-6823
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6823
  - https://github.com/HKUDS/OpenHarness/commit/fab40c6eabfb15f2bdf23cddd3cfe66a64ea203d
  - https://github.com/HKUDS/OpenHarness/pull/147
  - https://github.com/HKUDS/OpenHarness/releases/tag/v0.1.7
  - https://www.vulncheck.com/advisories/hkuds-openharness-insecure-default-remote-channel-allowlist
rules:
  - title: Detect OpenHarness Channel Configuration with Wildcard Allow List
    description: Detects OpenHarness channel configurations where 'allow_from' is set to a wildcard, indicating the insecure default configuration.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1556.006
    data_sources:
      - file_event
      - linux
  - title: Detect Unauthorized Access to OpenHarness Agent Runtimes
    description: Detects network connections to OpenHarness agent runtimes from unexpected source IP addresses, potentially indicating exploitation of the insecure default configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1556.006
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

HKUDS OpenHarness, a tool whose function is not explicitly defined in the source material, prior to the remediation implemented in pull request #147, exhibits an insecure default configuration. This vulnerability arises because remote channels inherit the setting `allow_from = ["*"]`. This overly permissive configuration allows any remote sender to bypass admission checks, effectively negating intended access controls. The vulnerability was reported on April 21, 2026. Exploitation requires an attacker to reach the configured channel, opening a pathway to host-backed agent runtimes. Successful exploitation can lead to unauthorized file disclosure and read access via default-enabled read-only tools within the OpenHarness environment. Defenders should ensure they are running a version of OpenHarness patched with PR #147 or later.

## Attack Chain

1.  Attacker gains network access to the OpenHarness instance.
2.  Attacker identifies a configured remote channel.
3.  Attacker leverages the inherited `allow_from = ["*"]` configuration to bypass admission controls.
4.  Attacker interacts with a host-backed agent runtime.
5.  Attacker exploits default-enabled read-only tools available within the runtime.
6.  Attacker gains unauthorized read access to sensitive files on the system.
7.  Attacker exfiltrates the disclosed files.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass intended access controls and gain unauthorized read access to files accessible to the OpenHarness agent. This could lead to the disclosure of sensitive information, potentially impacting confidentiality. The scope of the impact depends on the data accessible to the agent runtime and the sensitivity of those files. Given the default-enabled nature of the vulnerability, any OpenHarness deployment prior to PR #147 is potentially vulnerable.

## Recommendation

*   Upgrade HKUDS OpenHarness to a version including or following the remediation provided in [PR #147](https://github.com/HKUDS/OpenHarness/pull/147).
*   Monitor network connections to the OpenHarness instance for unexpected remote channel access, using a network monitoring solution.
*   Audit the configuration of OpenHarness channels to ensure that `allow_from` is not set to `["*"]`, but rather to a restrictive set of trusted senders.
