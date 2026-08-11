---
title: Remote Code Execution in JBoss Marshalling via Infinispan
slug: 2026-08-jboss-marshalling-rce
description: A deserialization vulnerability in JBoss Marshalling allows remote attackers to achieve code execution through the Infinispan session replication path.
date: "2026-08-11T09:48:03Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Red Hat
products:
  - JBoss Marshalling
  - Infinispan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Infinispan session replication path deserializes replicated session data via the JBoss Marshalling River unmarshaller with no class filtering — enabling RCE via deserialization gadget chains on every cluster node.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The flaw enables RCE via deserialization gadget chains on every cluster node.
    confidence_band: high
cves:
  - id: CVE-2026-15555
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15555
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch JBoss Marshalling and Infinispan components to versions addressing CVE-2026-15555.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-15555 remediation.
  mitigation_plan:
    - priority: immediate
      action: Isolate Infinispan replication traffic to authorized, trusted cluster networks only.
      owner: IT Operations
      addresses: CVE-2026-15555
      evidence: Exploitation relies on injecting malicious serialized session data into the replication stream.
---

A critical vulnerability (CVE-2026-15555) has been identified in JBoss Marshalling, specifically affecting the Infinispan session replication mechanism. The flaw exists because the Infinispan session replication path utilizes the JBoss Marshalling River unmarshaller to process replicated session data without implementing any class filtering. This architectural oversight allows an attacker capable of injecting malicious serialized session data into the replication stream to trigger deserialization gadget chains. Successful exploitation results in remote code execution (RCE) on all nodes participating in the affected cluster. Given the nature of session replication, this vulnerability poses a significant risk to distributed Java applications, as exploitation of a single cluster node can propagate to all other nodes. Defenders should prioritize auditing applications that use JBoss Marshalling or Infinispan, focusing on network traffic monitoring between cluster nodes and the application of vendor-supplied patches.

## Impact

Successful exploitation allows for unauthenticated remote code execution on all cluster nodes, potentially leading to full system compromise, data exfiltration, and lateral movement within the environment. Affected sectors include any enterprise environment utilizing JBoss or Infinispan for session state management.

## Recommendation

- Apply the security updates provided by Red Hat to remediate CVE-2026-15555 across all infrastructure.
- Audit network communication between Infinispan cluster nodes for anomalous serializable object traffic.
- Review application configurations to ensure strict class filtering is enforced during deserialization, if currently configured to use JBoss Marshalling.
