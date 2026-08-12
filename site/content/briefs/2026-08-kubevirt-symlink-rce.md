---
title: KubeVirt virt-handler Privilege Escalation via Symlink Injection
slug: 2026-08-kubevirt-symlink-rce
description: A symlink following vulnerability (CVE-2026-13622) in KubeVirt allows an attacker with pod execution permissions to escalate privileges and achieve full node compromise by redirecting migration proxy socket traffic.
date: "2026-08-12T22:52:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cloud
  - privilege-escalation
  - container-security
vendors:
  - KubeVirt
products:
  - KubeVirt
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker with namespace edit and pods/exec permissions can replace a migration proxy socket with a symlink to the host CRI-O socket... enabling full node compromise.
    confidence_band: high
cves:
  - id: CVE-2026-13622
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13622
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch KubeVirt to the version addressing CVE-2026-13622.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-13622 reported as critical symlink vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Audit RBAC for 'pods/exec' and namespace modification rights.
      owner: Security Operations
      addresses: CVE-2026-13622
      evidence: Exploitation requires 'pods/exec' and namespace edit permissions.
---

CVE-2026-13622 is a critical privilege escalation vulnerability identified in the KubeVirt virt-handler migration proxy. The flaw resides in the migration logic where virt-handler dials Unix sockets within a target virt-launcher pod using paths constructed via /proc/&lt;pid>/root/. Because the implementation fails to enforce symlink protection during this process, an attacker who has already obtained pod/exec or namespace edit permissions can manipulate the socket environment. 

The vulnerability is compounded by the fact that virt-handler executes with root privileges within the host mount namespace. By replacing a legitimate migration proxy socket with a symlink pointing to sensitive host-level sockets, such as the CRI-O socket, an attacker can trick the proxy into relaying traffic to the container runtime. This effectively allows the attacker to execute unauthorized commands at the node level, leading to a complete compromise of the underlying host.

## Attack Chain

1. Attacker gains initial access to a Kubernetes namespace with pod/exec and permissions to modify pod resources.
2. Attacker locates the qemu-owned directory within the target virt-launcher pod where migration sockets reside.
3. Attacker removes or renames the legitimate migration proxy socket file.
4. Attacker creates a malicious symlink at the original socket path, pointing the target to the host's CRI-O socket located at /var/run/crio/crio.sock.
5. Attacker triggers a live migration event within the KubeVirt environment to force virt-handler to initiate a connection.
6. virt-handler, running as root in the host mount namespace, follows the symlink and connects to the CRI-O socket.
7. virt-handler uses io.Copy to bridge the connection, allowing the attacker to relay malicious container runtime commands through the proxy.
8. Host-level container runtime processes the relayed commands, granting the attacker control over the node.

## Impact

Successful exploitation of CVE-2026-13622 results in a total loss of confidentiality, integrity, and availability for the affected KubeVirt node. Attackers can escape the container context to gain root access to the host machine, potentially leading to unauthorized access to all pods running on the compromised node, exfiltration of node-level secrets, and disruption of cluster operations.

## Recommendation

- Patch KubeVirt immediately to the latest version that includes the fix for CVE-2026-13622.
- Review Kubernetes RBAC policies to restrict 'pods/exec' and namespace modification permissions to the absolute minimum necessary personnel.
- Implement Pod Security Admissions or admission controllers to prevent unauthorized modification of sensitive container file paths.
