---
title: Unauthorized NFS Root Access via AUTH_SYS Credentials
slug: 2026-08-nfs-auth-sys-root-access
description: Detection of unauthorized NFS client access where a remote system asserts root-equivalent (UID 0) privileges over weak RPC/UNIX authentication, facilitating data collection and traversal.
date: "2026-08-01T01:41:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network
  - nfs
  - collection
  - rpc
products:
  - NFS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1039
    technique_name: Data from Network Shared Drive
    evidence: NFSv3 and NFSv4 clients can claim arbitrary UIDs through AUTH_SYS, and weak export controls may honor root-equivalent access from unexpected hosts.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: Attackers abuse this to read secrets, traverse exports, or stage ransomware writes without a local root shell on the NFS server.
    confidence_band: high
rules:
  - title: Detect First Time Seen NFS AUTH_SYS Root UID Access
    description: Detects an NFS client asserting root-equivalent UID 0 using the weak AUTH_SYS protocol, a potential precursor to unauthorized file access.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1039
      - T1213
    data_sources:
      - network_connection
rules_count: 1
---

NFS AUTH_SYS (RPC UNIX) authentication is inherently weak because it trusts the UID asserted by the client machine without cryptographic validation. When exported shares are configured without 'root_squash' or lack stronger authentication (like RPCSEC_GSS/Kerberos), an attacker can easily claim a UID of 0, effectively granting them superuser access to the exported filesystem. This vulnerability allows actors to bypass traditional permission models, enabling the exfiltration of sensitive files, directory enumeration, or the staging of malicious payloads for ransomware. This detection focuses on identifying the first-time observation of a source/destination IP pair using these weak credentials, which is a high-signal indicator of unauthorized reconnaissance or data collection activity within an environment.

## Attack Chain

1. Attacker performs internal network reconnaissance to identify reachable NFS export servers using tools like 'showmount' or 'rpcinfo'.
2. Attacker selects a target share and identifies that it permits AUTH_SYS (UNIX) authentication.
3. Attacker mounts the target NFS export from a controlled host, explicitly requesting the mount as UID 0 (root).
4. The NFS server validates the request based on IP-based export controls, failing to enforce 'root_squash' or Kerberos validation.
5. Attacker performs directory traversal or enumeration to identify high-value targets (e.g., configuration files, credentials, or databases).
6. Attacker initiates bulk read/copy operations of sensitive files or performs file manipulation (WRITE/RENAME) to stage ransomware impact.
7. Attacker unmounts the share and clears local logs or metadata to conceal the unauthorized activity.

## Impact

Successful exploitation allows unauthorized access to data stored on network-attached storage. In enterprise environments, this often leads to the exposure of credentials, database dumps, and intellectual property. The ability to write as root to an export can also result in the modification of system binaries or data, providing a vector for further lateral movement or automated ransomware deployment.

## Recommendation

* Deploy the provided detection logic to identify the first-time use of UID 0 over AUTH_SYS to alert on unauthorized client interaction.
* Enforce 'root_squash' on all sensitive '/etc/exports' configurations to prevent remote clients from exercising superuser permissions.
* Migrate sensitive NFS exports to 'sec=krb5' (RPCSEC_GSS) to ensure cryptographic authentication of client UIDs.
* Audit and restrict client IP allowlists in server export configurations to ensure only authorized infrastructure can access sensitive storage shares.
* Monitor for abnormal network traffic patterns from unauthorized hosts using the identified 'network_traffic.nfs' log source.
