---
title: Path Traversal and Arbitrary File Write in Flatpak
slug: 2026-09-flatpak-traversal
description: A vulnerability in Flatpak's extract_extra_data() allows malicious repositories to perform path traversal and write arbitrary files to the host filesystem, potentially leading to root access on system-wide installations.
date: "2026-09-24T02:45:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flatpak:flatpak:*:*:*:*:*:*:*:*
tags:
  - linux
  - flatpak
  - vulnerability
  - path-traversal
vendors:
  - Flatpak
products:
  - Flatpak
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: When Flatpak is configured for system-wide installs, this vulnerability can be exploited to achieve root-level file write access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The flaw allows a malicious or compromised repository to write arbitrary files to the host filesystem.
    confidence_band: high
cves:
  - id: CVE-2026-96275
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96275
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit and verify all configured Flatpak remotes for authorization.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96275 enables malicious repository exploitation.
  mitigation_plan:
    - priority: immediate
      action: Monitor for patches from distribution maintainers and apply immediately.
      owner: IT Operations
      addresses: CVE-2026-96275
      evidence: NVD vulnerability disclosure
---

CVE-2026-96275 identifies a critical flaw in Flatpak's handling of extra data sources, specifically within the extract_extra_data() function. The vulnerability stems from two combined weaknesses: the resolution of files/extra paths that incorrectly follow symbolic links and the failure to sanitize blob names defined in the xa.extra-data-sources configuration. An attacker operating a malicious or compromised Flatpak repository can use directory traversal sequences, such as '..', within these blob names to escape intended directories and write content to arbitrary locations on the host. When Flatpak is utilized for system-wide installations, this process executes with root privileges, allowing an attacker to overwrite system files, place unauthorized binaries, or modify configuration files. This impacts any system relying on Flatpak for application management where untrusted repositories might be configured.

## Impact

Successful exploitation allows for arbitrary file creation or modification on the host system. In scenarios involving system-wide Flatpak installations, this results in full root-level compromise of the host filesystem. This vulnerability affects Linux systems leveraging Flatpak for software distribution and management.

## Recommendation

Prioritized actions for administrators and security teams:

- Audit configured Flatpak remotes and repositories to ensure only trusted sources are authorized.
- Monitor for unauthorized additions of new Flatpak repositories on production systems.
- Prioritize updates to the Flatpak runtime and core binaries as soon as security patches are released by upstream maintainers.
- Implement file integrity monitoring (FIM) on critical system directories, particularly those frequently targeted for persistent modifications, to detect anomalous file writes occurring from the flatpak binary or associated helper processes.
