---
title: Authentication Bypass in PikiwiDB Pika Replication Server
slug: 2026-09-pikiwidb-auth-bypass
description: PikiwiDB Pika 3.5.7 suffers from an authentication bypass in its protobuf replication server, allowing unauthenticated remote attackers to synchronize data and manipulate replica nodes.
date: "2026-09-02T05:11:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pikiwidb:pika:3.5.7:*:*:*:*:*:*:*
vendors:
  - PikiwiDB
products:
  - Pika (3.5.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The service exposes a port... that does not authenticate incoming requests.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unauthenticated remote attacker can connect directly to the replication port and issue... requests, obtaining the full-sync snapshot.
    confidence_band: high
cves:
  - id: CVE-2026-84700
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84700
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Security
  immediate_actions:
    - action: Apply network segmentation/firewall rules to isolate the PikiwiDB replication port (ClientPort + 2000).
      owner: Infrastructure Security
      due: 24h
      evidence: The service exposes a port... that does not authenticate incoming requests.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Pika replication ports to known authorized replica IP addresses at the host or network firewall level.
      owner: IT Operations
      addresses: CVE-2026-84700
---

PikiwiDB (Pika) version 3.5.7 contains a critical authentication bypass vulnerability (CVE-2026-84700) within its internal protobuf replication server. The service exposes a secondary port, calculated as the default client port plus 2000 (e.g., 11221 for a default port of 9221), which fails to properly enforce authentication. While the Pika 'requirepass' configuration is intended to protect the replication interface, only the MetaSync handler specifically validates credentials. The frame dispatcher (DealMessage) fails to verify authentication or session state before routing incoming messages, such as TrySync, DBSync, BinlogSync, and RemoveSlaveNode, to their respective handlers. Consequently, an unauthenticated remote attacker can connect directly to the exposed replication port to exfiltrate full-sync snapshots, monitor live write streams, or disrupt database replication by removing slave nodes, regardless of the security settings configured on the primary client interface.

## Impact

Successful exploitation allows for the unauthorized exfiltration of sensitive database content and full-sync snapshots, potentially leading to complete data exposure. Attackers can also disrupt database availability and integrity by force-removing legitimate replica nodes. This vulnerability affects Pika 3.5.7, which is often deployed in high-performance storage environments where data replication is critical.

## Recommendation

1. Restrict network access to the PikiwiDB replication port to authorized internal nodes only via firewall rules, as the service does not enforce authentication.
2. Audit environment configurations for Pika 3.5.7 deployments and restrict management/replication port exposure from public or untrusted network segments.
3. Monitor internal network traffic for unexpected connections originating from non-replica nodes to the calculated Pika replication port (default client port + 2000).
