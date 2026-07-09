---
title: 'CVE-2026-59996: OpenSSH scp File Placement Vulnerability'
slug: 2026-07-openssh-scp-file-placement
description: CVE-2026-59996 details a vulnerability in OpenSSH's `scp` utility, allowing a remote attacker to cause a copied file to be placed in a parent directory of the intended destination during a remote-to-remote transfer, potentially leading to unintended file system modification.
date: "2026-07-09T07:40:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - scp
  - openssh
  - linux
  - macos
vendors:
  - OpenSSH
products:
  - OpenSSH before 10.4
affected_os:
  - Linux
  - macOS
cves:
  - id: CVE-2026-59996
    cvss: 4.2
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59996
---

A vulnerability, identified as CVE-2026-59996, affects the `scp` utility within OpenSSH versions prior to 10.4. This flaw permits an attacker to deviate the intended destination of a file transfer when a copy operation is performed between two remote hosts. Specifically, the `scp` utility may incorrectly place the copied file into a parent directory relative to the user's specified target. This issue, disclosed by Microsoft, highlights a potential for unintended file system modifications. While not an immediate remote code execution, successful exploitation could enable attackers to overwrite critical system files, place malicious configurations, or stage executables in unexpected locations, subsequently aiding in privilege escalation or further system compromise. Organizations utilizing OpenSSH with `scp` for remote-to-remote transfers should prioritize patching to mitigate this risk.

## Attack Chain

1. A legitimate user initiates an `scp` command to transfer a file between two remote hosts using an OpenSSH client/server ecosystem that includes a vulnerable version of the `scp` utility (prior to 10.4).
2. One of the remote hosts (either the source or destination for the file transfer) is under the control of an attacker, or the attacker can influence the file path/name specified in the transfer.
3. During the remote-to-remote `scp` transfer, the attacker exploits CVE-2026-59996 by manipulating specific input or file path details sent to the vulnerable `scp` utility.
4. The vulnerable `scp` utility on the destination host processes the manipulated input incorrectly due to a path traversal-like vulnerability.
5. As a result, the transferred file is placed in a parent directory on the destination host, outside of the intended target directory specified by the user.
6. This unintended file placement could lead to overwriting critical system files, placing malicious configuration files, or staging malicious executables in sensitive locations, potentially leading to privilege escalation, arbitrary code execution, or further system compromise.

## Impact

The primary impact of CVE-2026-59996 is unintended file placement on a target system. While not directly leading to remote code execution, a successful exploit could allow an attacker to overwrite crucial system files, leading to denial of service or system instability, or to place malicious files in locations where they could be executed by legitimate system processes or users, facilitating further compromise, privilege escalation, or persistence. The exact scope of impact depends on the specific file overwritten or placed and its location within the file system.

## Recommendation

* Immediately patch all OpenSSH installations to version 10.4 or later to remediate CVE-2026-59996.
* Review configurations of `scp` and SSH to ensure only necessary file transfers are permitted and validate paths.
