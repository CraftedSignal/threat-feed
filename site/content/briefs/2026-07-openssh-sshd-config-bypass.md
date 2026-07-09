---
title: 'CVE-2026-59999: OpenSSH sshd Configuration Bypass via PermitTunnel'
slug: 2026-07-openssh-sshd-config-bypass
description: A logic error in OpenSSH's sshd daemon before version 10.4 allowed the PermitTunnel configuration to take precedence over DisableForwarding=yes, leading to unintended SSH tunnel establishment and potential unauthorized network access through the tunnel feature.
date: "2026-07-09T07:42:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssh
  - openssh
  - vulnerability
  - configuration-bypass
  - linux
  - macos
vendors:
  - OpenSSH
products:
  - OpenSSH (< 10.4)
affected_os:
  - Linux
  - macOS
cves:
  - id: CVE-2026-59999
    cvss: 5.9
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59999
---

The Microsoft Security Response Center (MSRC) has published details on CVE-2026-59999, a logic error affecting the `sshd` component of OpenSSH versions prior to 10.4. This vulnerability stems from an incorrect precedence rule when `DisableForwarding=yes` and `PermitTunnel=yes` are simultaneously configured in the `sshd_config` file. Despite an administrator's intention to prevent SSH forwarding via `DisableForwarding=yes`, the `PermitTunnel=yes` option inadvertently takes precedence, enabling an authenticated attacker to establish an SSH tunnel. This bypass of intended security controls creates a pathway for attackers to circumvent network segmentation, access internal services, or exfiltrate data from environments where SSH forwarding was presumed to be blocked. The vulnerability was disclosed on July 9, 2026.

## Attack Chain

1. An attacker gains authenticated access (e.g., via stolen credentials or another vulnerability) to a server running a vulnerable `sshd` instance (OpenSSH prior to version 10.4).
2. The target `sshd` server's configuration (`sshd_config`) contains a conflicting setup where both `DisableForwarding=yes` and `PermitTunnel=yes` are enabled.
3. The attacker attempts to establish an SSH tunnel, such as local port forwarding, remote port forwarding, or a SOCKS proxy, from their client to the compromised server.
4. The vulnerable `sshd` process on the server incorrectly prioritizes `PermitTunnel=yes` over `DisableForwarding=yes` due to the logic error, allowing the tunnel setup.
5. An unauthorized SSH tunnel is successfully established, bypassing the administrator's intended security policy to disable forwarding.
6. The attacker then utilizes this tunnel to circumvent network access controls or firewall rules, enabling connections to internal network resources that would otherwise be unreachable.
7. This unauthorized network access allows the attacker to conduct further reconnaissance, pivot deeper into the network, exfiltrate sensitive data, or deploy additional malicious tools.

## Impact

The successful exploitation of CVE-2026-59999 allows an authenticated attacker to bypass intended network security policies, specifically those designed to prevent SSH forwarding. This can lead to unauthorized network access, enabling attackers to circumvent firewall rules, reach internal systems, or pivot to otherwise isolated network segments. While no specific victim counts or sectors have been reported, any organization utilizing OpenSSH `sshd` with the described conflicting configuration is at risk of unauthorized internal network traversal and potential data exfiltration or further compromise.

## Recommendation

* Immediately patch OpenSSH `sshd` to version 10.4 or later to remediate CVE-2026-59999.
* Review all `sshd_config` files across your infrastructure to ensure that if `DisableForwarding=yes` is intended, `PermitTunnel=no` is explicitly set or omitted (as `no` is often the default).
* Audit your network for unusual SSH tunnel activity, as this vulnerability bypasses configuration rather than introducing novel network signatures.
