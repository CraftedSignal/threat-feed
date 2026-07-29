---
title: DNS Enumeration in Linux Containers by Adversaries
slug: 2026-07-dns-enumeration-container
description: Adversaries leverage DNS enumeration tools such as nslookup, dig, host, or getent hosts inside compromised Linux containers to discover internal Kubernetes services and network configuration, facilitating lateral movement and further exploitation.
date: "2026-07-29T12:39:49Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container
  - kubernetes
  - linux
  - discovery
  - threat-detection
products:
  - Kubernetes
  - CoreDNS
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: This rule flags use of DNS utilities (nslookup, dig, host, or getent hosts) inside a Linux container that query internal Kubernetes names such as kubernetes.default or *.svc.cluster.local, signaling in-cluster service discovery.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: This rule flags use of DNS utilities (nslookup, dig, host, or getent hosts) inside a Linux container that query internal Kubernetes names such as kubernetes.default or *.svc.cluster.local, signaling in-cluster service discovery.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: After compromising a pod, an attacker opens an interactive shell and runs nslookup kubernetes.default or dig *.svc.cluster.local to enumerate services and namespaces, map reachable endpoints, and stage lateral movement toward the API server, internal dashboards, or other pods.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: This rule flags use of DNS utilities (nslookup, dig, host, or getent hosts) inside a Linux container that query internal Kubernetes names such as kubernetes.default or *.svc.cluster.local, signaling in-cluster service discovery.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: This rule flags use of DNS utilities (nslookup, dig, host, or getent hosts) inside a Linux container that query internal Kubernetes names such as kubernetes.default or *.svc.cluster.local, signaling in-cluster service discovery.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_dns_enumeration.toml
iocs:
  - type: domain
    value: kubernetes.default
  - type: domain
    value: '*.svc.cluster.local'
  - type: domain
    value: '*.cluster.local'
  - type: filepath
    value: /var/run/secrets/kubernetes.io/serviceaccount
  - type: url
    value: https://kubernetes.default
ioc_counts:
  domain: 3
  filepath: 1
  url: 1
rules:
  - title: Detect DNS Enumeration in Linux Containers
    description: Detects the execution of DNS enumeration tools (nslookup, dig, host, getent hosts) inside a Linux container querying internal Kubernetes names (kubernetes.default, *.svc.cluster.local). This indicates post-compromise reconnaissance.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
      - T1018
      - T1046
      - T1049
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief details how adversaries perform reconnaissance within compromised Linux containers by executing DNS enumeration tools like `nslookup`, `dig`, `host`, or `getent hosts`. This activity, detected by Elastic Defend for Containers, aims to map the internal network configuration of the container, identify Kubernetes services, and discover domains within the cluster. By querying internal Kubernetes names such as `kubernetes.default`, `*.svc.cluster.local`, or `*.cluster.local`, attackers gain crucial information about reachable endpoints. This post-compromise activity is a key precursor to lateral movement, privilege escalation, and access to sensitive resources like the Kubernetes API server or service account tokens, ultimately enabling further malicious actions within the environment. This technique is often observed after an initial compromise, when an attacker has obtained interactive shell access to a pod.

## Attack Chain

1. **Initial Compromise**: An adversary successfully compromises a Linux container within a Kubernetes environment, typically through a vulnerable application or misconfiguration.
2. **Interactive Shell Access**: The attacker establishes interactive shell access to the compromised pod, allowing direct command execution within the container.
3. **DNS Enumeration Tool Execution**: The adversary executes standard DNS enumeration utilities like `nslookup`, `dig`, `host`, or `getent hosts` from within the container's shell.
4. **Kubernetes Service Discovery**: These tools are used to query internal Kubernetes-specific hostnames and domain patterns, such as `kubernetes.default`, `*.svc.cluster.local`, or `*.cluster.local`.
5. **Network Mapping and Reconnaissance**: The results of these queries provide the attacker with information about the cluster's network configuration, available internal services, and reachable endpoints.
6. **Credential Access Attempt**: The adversary may attempt to access sensitive files like `/var/run/secrets/kubernetes.io/serviceaccount` to retrieve service account tokens, which can be used for authentication and privilege escalation.
7. **Lateral Movement Staging**: Based on the gathered intelligence, the attacker plans and executes lateral movement towards the Kubernetes API server, internal dashboards, or other high-value pods, expanding their control over the cluster.

## Impact

Successful DNS enumeration within a compromised container allows adversaries to gain a detailed understanding of the Kubernetes cluster's internal network and service topology. This knowledge enables attackers to identify critical internal services, map potential targets for further exploitation, and circumvent security controls. The ultimate impact can include unauthorized access to the Kubernetes API server, exfiltration of sensitive data, deployment of malicious workloads, or complete compromise of the cluster leading to widespread service disruption or data breaches. While this specific activity is a reconnaissance phase, it is a critical step towards more severe consequences.

## Recommendation

* Deploy the Sigma rule "Detect DNS Enumeration in Linux Containers" to your SIEM for real-time monitoring of suspicious activity.
* Configure Kubernetes audit logs to capture `kubectl exec/attach` or ephemeral container launches, and correlate with the `container.id` from alerts.
* Review DNS and network telemetry from affected pods (e.g., CoreDNS logs, CNI flow logs) to trace queried hostnames and subsequent connections to internal services or the API server.
* Isolate any affected pods immediately by applying a deny-egress NetworkPolicy to the CoreDNS service and cluster service CIDRs, and consider rotating affected service account tokens.
* Harden your Kubernetes environment by restricting `exec/attach` capabilities via RBAC, enforcing Pod Security Standards to disallow unauthorized ephemeral containers, limiting egress from pods with NetworkPolicies, and utilizing distroless or stripped-down container images that omit unnecessary utilities like DNS enumeration tools.
