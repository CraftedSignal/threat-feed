---
title: Remote Code Execution Vulnerability in SUSE NeuVector
slug: 2026-09-suse-neuvector-rce
description: An OS command injection vulnerability in the packet-capture filter component of SUSE NeuVector allows for unauthenticated remote code execution on affected Kubernetes nodes.
date: "2026-09-28T22:19:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - kubernetes
  - cloud-native
vendors:
  - SUSE
products:
  - NeuVector (< 5.4.11, < 5.5.4, < 5.6.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability is an OS command injection flaw in the packet-capture (sniffer) filter leading to remote code execution.
    confidence_band: high
references:
  - https://github.com/neuvector/neuvector/security/advisories/GHSA-vr77-8vmq-qfmj
  - https://www.suse.com/support/update/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all NeuVector deployments to version 5.4.11, 5.5.4, 5.6.2, or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies these as the patched versions
  mitigation_plan:
    - priority: immediate
      action: Upgrade NeuVector containers to the patched versions
      owner: IT Operations
      addresses: OS Command Injection in Packet-Capture Filter
      evidence: Source advisory
---

SUSE has identified a critical vulnerability in the NeuVector container security platform affecting specific versions of the product. The issue lies within the packet-capture (sniffer) filter functionality, which fails to properly sanitize inputs, resulting in an OS command injection flaw. An attacker capable of interacting with the packet-capture configuration can leverage this vulnerability to execute arbitrary commands with the privileges of the NeuVector service. Because NeuVector components typically operate with elevated permissions to monitor network traffic within a Kubernetes cluster, successful exploitation grants the attacker Remote Code Execution (RCE) on the underlying Kubernetes nodes hosting the vulnerable containers. This poses a significant risk to cluster integrity and container isolation. Affected versions include those prior to 5.4.11, 5.5.4, and 5.6.2. Administrators should prioritize updating NeuVector deployments to the patched versions to mitigate potential cluster-wide compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve full code execution on the underlying host nodes in a Kubernetes environment. This level of access typically results in complete container escape, persistent access to the cluster, potential exfiltration of sensitive secrets and service tokens stored in the cluster, and disruption of critical business services. No specific incident count or sector targeting was provided in the advisory, but all organizations leveraging NeuVector within Kubernetes environments are at risk.

## Recommendation

Prioritize upgrading all NeuVector instances to versions 5.4.11, 5.5.4, 5.6.2, or later to eliminate the command injection vector. Audit Kubernetes cluster role and container security policy logs for anomalous process execution patterns originating from NeuVector pods.
