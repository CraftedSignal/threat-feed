---
title: OpenClaw Access Control Bypass Vulnerability
slug: 2026-04-openclaw-bypass
description: OpenClaw before 2026.3.22 allows attackers to circumvent profile restrictions via persistent profile mutation and runtime profile selection, leading to unauthorized access.
date: "2026-04-23T22:16:42Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - access-control
  - bypass
  - openclaw
  - cve-2026-41353
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41353
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41353
  - https://github.com/openclaw/openclaw/commit/eac93507c36ccd0c359fba18fa466ef6448be8a5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-h5hg-h7rr-gpf3
  - https://www.vulncheck.com/advisories/openclaw-allowprofiles-bypass-via-profile-mutation-and-runtime-selection
rules:
  - title: Detect OpenClaw Profile Mutation
    description: Detects potential attempts to mutate OpenClaw profiles, indicative of CVE-2026-41353 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - file_event
      - windows
  - title: Detect OpenClaw Runtime Profile Selection
    description: Detects potential attempts to select restricted profiles at runtime, indicative of CVE-2026-41353 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw, a software application, is vulnerable to an access control bypass (CVE-2026-41353) affecting versions prior to 2026.3.22. This vulnerability resides in the `allowProfiles` feature, enabling attackers to bypass intended access controls. The exploitation involves manipulating browser proxy profiles at runtime through persistent profile mutation and runtime profile selection. This allows remote attackers to gain access to restricted profiles. This poses a significant risk to environments relying on OpenClaw for profile-based access control, as it can lead to unauthorized data access and privilege escalation. This vulnerability was published on April 23, 2026.

## Attack Chain

1.  Attacker gains initial access to a system with OpenClaw installed.
2.  The attacker identifies the targeted restricted profile.
3.  Attacker exploits the `allowProfiles` feature by persistently mutating the profile configuration.
4.  The attacker manipulates browser proxy profiles at runtime to bypass access controls.
5.  The attacker selects the restricted profile during runtime.
6.  OpenClaw incorrectly authorizes the attacker, granting access to the restricted profile.
7.  Attacker leverages the unauthorized access to perform privileged actions.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass intended access controls and gain unauthorized access to restricted profiles within OpenClaw. This can lead to the compromise of sensitive information, privilege escalation, and potential disruption of services. The impact is significant for organizations relying on OpenClaw for access control, as it undermines the security measures intended to protect sensitive resources.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.22 or later to patch CVE-2026-41353.
*   Implement the following Sigma rule to detect potential exploitation attempts by monitoring for profile manipulation.
*   Monitor OpenClaw logs for suspicious profile changes or runtime profile selections indicative of exploitation.
