---
title: CVE-2026-53791 - IP Address Spoofing in rsync Daemon
slug: 2026-08-rsync-spoofing
description: The rsync daemon before version 3.5.0 contains a vulnerability where unauthenticated attackers can inject a forged PROXY protocol header to bypass IP-based access control restrictions.
date: "2026-08-13T15:37:26Z"
lastmod: "2026-08-13T15:40:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rsync
  - vulnerability
  - cve-2026-53791
  - spoofing
  - access-control-bypass
  - file-read
vendors:
  - rsync
products:
  - rsync
  - rsync (< 3.5.0)
  - rsync (3.1.0 to 3.4.x)
  - rsync (3.1.0-3.4.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Attackers who can connect directly to the rsync daemon can inject a spoofed source IP in the PROXY protocol header to circumvent hosts allow/deny rules.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: rsync before 3.5.0 contains an arbitrary file read vulnerability that allows attackers to read files accessible to the rsync daemon process by exploiting symlink following
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: When a DNS lookup for a hostname-based deny rule fails, the daemon skips the rule rather than defaulting to a deny decision.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The auth users parser uses comma-only tokenization when splitting the user list, which fails to correctly handle entries of the form @Group Name where the group name contains a space.
    confidence_band: high
cves:
  - id: CVE-2026-53791
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53791
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53802
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70452
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70463
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade rsync to 3.5.0+
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-53791 advisory
  mitigation_plan:
    - priority: immediate
      action: Disable PROXY protocol in rsync daemon configuration if not in use
      owner: IT Operations
      addresses: CVE-2026-53791
      evidence: Vulnerability involves PROXY protocol header processing
updates:
  - at: "2026-08-13T15:38:33Z"
    level: L2
    summary: added coverage for rsync (< 3.5.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-53802
  - at: "2026-08-13T15:39:17Z"
    level: L2
    summary: added coverage for rsync (3.1.0 to 3.4.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70452
  - at: "2026-08-13T15:40:22Z"
    level: L2
    summary: added coverage for rsync (3.1.0-3.4.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70463
---

The rsync daemon (rsyncd), a popular file synchronization utility, is vulnerable to an IP address spoofing flaw in versions prior to 3.5.0. An unauthenticated remote attacker capable of establishing a direct connection to the rsync service can exploit the daemon's handling of the PROXY protocol. By injecting a crafted PROXY protocol header, an attacker can substitute the true source IP address with a spoofed IP address. 

This bypasses configured hosts.allow and hosts.deny access control lists, which rely on the connection source IP for authorization decisions. If an attacker identifies an environment that uses source-IP-based authentication for rsync, they can spoof an address identified as authorized to gain unauthorized access to the filesystem. This vulnerability is particularly critical in environments where rsync is exposed to untrusted networks or where the daemon relies solely on IP-based security primitives for protecting sensitive directory trees.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass network-level access controls, potentially resulting in unauthorized file reads or writes on the rsync server. This poses a significant risk to data integrity and confidentiality in environments that rely on IP-based trust models for file synchronization.

## Recommendation

* Upgrade all instances of rsync to version 3.5.0 or later to remediate the vulnerability associated with CVE-2026-53791.
* Audit rsync configurations that utilize the PROXY protocol and consider disabling it if not strictly required.
* Transition from IP-based access controls to stronger authentication mechanisms, such as SSH-based rsync, which provides cryptographically verified identity, independent of the source connection IP.
* Restrict network access to rsync daemons at the firewall level to only include explicitly trusted hosts.
