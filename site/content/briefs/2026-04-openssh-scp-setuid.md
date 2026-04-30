---
title: OpenSSH scp Insecure File Permission Vulnerability (CVE-2026-35385)
slug: 2026-04-openssh-scp-setuid
description: OpenSSH versions before 10.3 allow for the potential installation of setuid or setgid files when using scp to download files as root with the -O option (legacy SCP protocol) and without the -p option (preserve mode), contrary to user expectations.
date: "2026-04-02T17:16:27Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

OpenSSH, a suite of secure networking utilities based on the Secure Shell (SSH) protocol, is affected by a vulnerability (CVE-2026-35385) in versions prior to 10.3. The vulnerability arises when using the `scp` command to download files as the root user with the `-O` (legacy SCP protocol) option and without the `-p` option (preserve mode). In this specific scenario, the downloaded file may be inadvertently installed with the setuid or setgid bits set. This behavior contradicts the expectations of some users, potentially leading to privilege escalation or other security misconfigurations. The vulnerability was publicly disclosed on April 2, 2026.

## Attack Chain

1.  Attacker gains access to a system where a user has `scp` installed and configured to connect to a remote server.
2.  The user, operating as root, initiates an `scp` download using the command `scp -O user@host:/path/to/file /local/path/`. The `-p` option is omitted, and the `-O` flag is used, triggering the legacy SCP protocol.
3.  The remote server serves the file `/path/to/file`. This file could have the setuid or setgid bits set.
4.  `scp`, due to the vulnerability, incorrectly handles the file permissions during the download process.
5.  The downloaded file is placed at `/local/path/` with the setuid or setgid bits unexpectedly preserved from the remote server.
6.  A local user executes the downloaded file `/local/path/`.
7.  If the setuid or setgid bit is set, the process executes with elevated privileges, potentially leading to unauthorized access or modification of system resources.

## Impact

Successful exploitation of this vulnerability can lead to unintended privilege escalation on the affected system. If a user downloads a file with the setuid bit set, an attacker could potentially execute the file with the privileges of the file owner (typically root). While the vulnerable scenario requires the user to be root and explicitly use the `-O` flag without `-p`, it can still represent a significant risk in environments where legacy SCP usage is prevalent or where users are unaware of the implications of these options. This scenario may affect a limited number of users who are using the specific vulnerable configuration.

## Recommendation

*   Upgrade OpenSSH to version 10.3 or later to patch the vulnerability (https://www.openssh.org/releasenotes.html#10.3p1).
*   Avoid using the `-O` option (legacy SCP protocol) with `scp`, especially when downloading files as the root user. Use `sftp` or `rsync` as a more secure alternative.
*   Always use the `-p` option to preserve file permissions when downloading files with `scp` to ensure that the downloaded file's permissions are explicitly controlled.
*   Deploy the Sigma rule provided below to detect the usage of `scp` with the `-O` flag, which is indicative of using the vulnerable legacy protocol.
