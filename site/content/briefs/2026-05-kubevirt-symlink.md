---
title: KubeVirt virt-handler Symlink Vulnerability Leading to Container Escape (CVE-2026-7374)
slug: 2026-05-kubevirt-symlink
description: CVE-2026-7374 allows an authenticated OpenShift user with edit permissions in a single namespace to escalate privileges to full cluster control by exploiting improper symlink validation in KubeVirt's virt-handler component when connecting to VM console sockets.
date: "2026-05-26T14:20:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - kubeVirt
  - openshift
  - symlink
  - container escape
  - privilege escalation
vendors:
  - KubeVirt
  - Red Hat
products:
  - virt-handler
  - OpenShift
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
cves:
  - id: CVE-2026-7374
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7374
rules:
  - title: Detect Suspicious Console Socket Symlink Creation
    description: Detects creation of symbolic links replacing console sockets, indicative of CVE-2026-7374 exploitation
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - file_event
      - linux
  - title: Detect CRI-O Socket Activity from Unusual Processes
    description: Detects CVE-2026-7374 exploitation — Monitors for processes interacting with the CRI-O socket outside of expected container runtime components
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-7374 is a critical vulnerability within KubeVirt's virt-handler component, enabling privilege escalation within OpenShift environments. An authenticated user with edit permissions in a single namespace can exploit improper symlink validation during virtual machine console connections. By manipulating the console socket, an attacker can redirect virt-handler's privileged connection to the host's container runtime (CRI-O) socket. This redirection allows the attacker to interact with any Unix socket on the host system, potentially leading to complete control over the node and, ultimately, the entire OpenShift cluster. This vulnerability poses a significant risk to cloud-native infrastructure and requires immediate attention from security teams.

## Attack Chain

1.  The attacker obtains valid credentials for an OpenShift user with edit permissions within a namespace.
2.  The attacker identifies a running virtual machine managed by KubeVirt within the namespace.
3.  The attacker replaces the console socket associated with the target VM with a symbolic link. This symlink points to the CRI-O socket of the host.
4.  When virt-handler attempts to establish a console connection to the VM, it unknowingly connects to the CRI-O socket due to the symlink.
5.  The attacker hijacks virt-handler's privileged connection to the CRI-O socket.
6.  Using the hijacked connection, the attacker interacts with the CRI-O socket to execute commands on the host.
7.  The attacker leverages the access gained to the host system to further escalate privileges and potentially compromise the node.
8.  The attacker expands their control from the compromised node to the entire OpenShift cluster, potentially exfiltrating data or deploying malicious workloads.

## Impact

Successful exploitation of CVE-2026-7374 grants an attacker full control over the targeted node and potentially the entire OpenShift cluster. This can lead to data breaches, denial of service, and the deployment of malicious containers within the environment. Given the broad adoption of KubeVirt and OpenShift, this vulnerability represents a significant risk to organizations utilizing these technologies, potentially impacting hundreds or thousands of nodes within a cluster if left unpatched.

## Recommendation

*   Apply the KubeVirt patch addressing CVE-2026-7374 immediately.
*   Implement monitoring to detect unauthorized modifications of console sockets (see Sigma rule "Detect Suspicious Console Socket Symlink Creation").
*   Monitor for unexpected processes interacting with the CRI-O socket (see Sigma rule "Detect CRI-O Socket Activity from Unusual Processes").
*   Enforce strict RBAC policies to minimize the number of users with edit permissions within namespaces.
