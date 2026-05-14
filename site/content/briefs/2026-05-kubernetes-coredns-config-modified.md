---
title: Kubernetes CoreDNS or Kube-DNS Configuration Modified
slug: 2026-05-kubernetes-coredns-config-modified
description: Modification of the CoreDNS or kube-dns ConfigMap in the kube-system namespace can lead to cluster-wide DNS poisoning, enabling man-in-the-middle attacks against internal services and the Kubernetes API server.
date: "2026-05-14T16:49:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - dns
  - man-in-the-middle
  - impact
products:
  - kubernetes
  - coredns
  - kube-dns
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/
  - https://coredns.io/plugins/rewrite/
  - https://attack.mitre.org/techniques/T1565/001/
rules:
  - title: Detect Kubernetes CoreDNS ConfigMap Modification
    description: Detects modifications to the CoreDNS or kube-dns ConfigMap in the kube-system namespace. This may indicate an attempt to poison DNS resolution within the cluster.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
      - T1565.001
    data_sources:
      - auditd
      - kubernetes
  - title: Detect Kubernetes DNS ConfigMap Modification - RBAC bypass attempt
    description: Detects modifications to the CoreDNS or kube-dns ConfigMap in the kube-system namespace, explicitly looking for failed authorization decisions.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565
      - T1565.001
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

The rule detects modifications to the CoreDNS or kube-dns ConfigMap within the kube-system namespace. These ConfigMaps are crucial for managing cluster DNS resolution, affecting all pods within the Kubernetes environment. An attacker compromising this configuration can redirect internal service DNS names to attacker-controlled IP addresses. This manipulation facilitates man-in-the-middle (MitM) attacks targeting sensitive internal endpoints such as the Kubernetes API server and database services. DNS poisoning at the cluster level is particularly impactful as it affects every pod across all namespaces without requiring modifications to individual workloads. CoreDNS configuration changes are typically infrequent, making any unexpected modifications a critical indicator of potential compromise.

## Attack Chain

1.  Attacker gains unauthorized access to a Kubernetes cluster, possibly through compromised credentials or a software vulnerability.
2.  The attacker identifies the CoreDNS or kube-dns ConfigMap within the kube-system namespace as a target for manipulation.
3.  The attacker modifies the Corefile content within the ConfigMap to redirect DNS queries for internal services to attacker-controlled IPs. This can be done using `kubectl edit configmap coredns -n kube-system` or similar commands.
4.  When pods within the cluster attempt to resolve internal service names, the poisoned DNS server returns the attacker's IP address.
5.  The victim pod connects to the attacker-controlled IP, believing it to be the legitimate service endpoint.
6.  The attacker intercepts traffic, potentially capturing sensitive data such as service account tokens, database credentials, and API communications.
7.  The attacker leverages stolen credentials and intercepted API traffic to further compromise the Kubernetes cluster and access sensitive resources.
8.  The attacker maintains persistence by ensuring the modified CoreDNS configuration remains in place, affecting all new pods that resolve DNS via the cluster DNS.

## Impact

A successful attack can compromise the entire Kubernetes cluster by redirecting traffic intended for critical internal services to malicious endpoints. This allows attackers to steal sensitive data such as service account tokens and database credentials, potentially leading to full control of the cluster. The attack affects all pods in all namespaces, creating a widespread security incident. Successful exploitation can also disrupt services that rely on DNS resolution, leading to denial of service conditions.

## Recommendation

*   Implement the Sigma rule `Detect Kubernetes CoreDNS ConfigMap Modification` to detect unauthorized modifications to the CoreDNS or kube-dns ConfigMap.
*   Restrict RBAC permissions to prevent unauthorized users from modifying DNS ConfigMaps in the kube-system namespace, as mentioned in the rule documentation.
*   Regularly audit ConfigMap changes in the kube-system namespace, as described in the rule's triage and analysis section.
*   Monitor Kubernetes audit logs for suspicious activity related to DNS configuration changes using the provided query in the rule definition.
