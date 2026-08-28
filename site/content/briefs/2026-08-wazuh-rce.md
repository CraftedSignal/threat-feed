---
title: Wazuh Cluster Mode Insecure Deserialization Vulnerability (CVE-2026-25769)
slug: 2026-08-wazuh-rce
description: An insecure deserialization vulnerability in Wazuh cluster communication allows a compromised worker node to achieve remote code execution as root on the master node.
date: "2026-08-28T19:17:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - wazuh
vendors:
  - Wazuh
products:
  - Wazuh (< 4.14.3)
cves:
  - id: CVE-2026-25769
    cvss: 9.1
    epss: 0.0879
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-25769
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Wazuh nodes to version 4.14.3 or later
      owner: IT Operations
      due: 24h
      evidence: Source specifies 4.14.3 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict Wazuh cluster communication ports to authorized node IPs only
      owner: IT Operations
      addresses: CVE-2026-25769
      evidence: Exploit requires communication from worker to master node.
---

CVE-2026-25769 is a critical insecure deserialization vulnerability affecting the cluster communication mechanism in Wazuh versions prior to 4.14.3. The flaw resides in how the Wazuh master node processes serialized data received from worker nodes within the cluster architecture. If an attacker successfully compromises a single worker node, they can leverage this vulnerability to send maliciously crafted serialized objects to the master node. Upon deserialization, these objects facilitate arbitrary command execution with root privileges on the master node. Given the high CVSS score of 9.1, this vulnerability poses a severe risk to the integrity of the entire security monitoring infrastructure, as a compromise of a worker node leads to a full takeover of the central management server.

## Impact

Successful exploitation allows for full system compromise of the Wazuh master node with root-level access. This results in the complete loss of confidentiality, integrity, and availability for the security monitoring platform, potentially enabling attackers to disable detection capabilities, exfiltrate security logs, or pivot further into the internal network.

## Recommendation

Prioritized actions for security operations and IT teams:

- Upgrade all Wazuh instances in cluster configurations to version 4.14.3 or later immediately to patch CVE-2026-25769.
- Restrict network access to the Wazuh cluster communication ports strictly to authorized worker nodes using host-based firewalls or network access control lists.
- Audit existing Wazuh worker nodes for signs of prior compromise, as a compromised worker is the prerequisite for exploiting this vulnerability.
- Review cluster communication logs for anomalies in traffic patterns or unexpected payload sizes originating from worker nodes.
