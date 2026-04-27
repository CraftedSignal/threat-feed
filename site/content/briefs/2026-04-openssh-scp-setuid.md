---
title: OpenSSH scp Insecure File Permission Vulnerability (CVE-2026-35385)
slug: 2026-04-openssh-scp-setuid
description: OpenSSH versions before 10.3 allow for the potential installation of setuid or setgid files when using scp to download files as root with the -O option (legacy SCP protocol) and without the -p option (preserve mode), contrary to user expectations.
date: "2026-04-02T17:16:27Z"
severities:
  - medium
tags:
  - openssh
  - scp
  - privilege-escalation
  - cve-2026-35385
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-35385
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35385
  - https://marc.info/?l=openssh-unix-dev&m=177513443901484&w=2
  - https://www.openssh.org/releasenotes.html#10.3p1
  - https://www.openwall.com/lists/oss-security/2026/04/02/3
rules:
  - title: Detect scp Usage with Legacy Protocol Option (-O)
    description: Detects the use of scp command with the -O option, indicating the use of the legacy SCP protocol, which is related to CVE-2026-35385.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1548
    data_sources:
      - process_creation
      - linux
  - title: Detect scp Usage without Preserving Permissions (-p)
    description: Detects the use of scp command without the -p option, which may lead to unintended permission issues. This can amplify the risk of CVE-2026-35385 if combined with the -O option.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1548
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenSSH, a suite of secure networking utilities based on the Secure Shell (SSH) protocol, is affected by a vulnerability (CVE-2026-35385) in versions prior to 10.3. The vulnerability arises when using the `scp` command to download files as the root user with the `-O` (legacy SCP protocol) option and without the `-p` option (preserve mode). In this specific scenario, the downloaded file may be inadvertently installed with the setuid or setgid bits set. This behavior contradicts the expectations…
