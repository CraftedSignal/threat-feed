---
title: Rancher local-path-provisioner Vulnerable to HelperPod Template Injection (CVE-2026-44543)
slug: 2026-05-local-path-provisioner-template-injection
description: A malicious user with permission to edit the `local-path-config` ConfigMap in the `local-path-storage` namespace can manipulate the `helperPod.yaml` template used by `rancher/local-path-provisioner`. Security-sensitive fields such as `securityContext.privileged`, `hostPath` volumes, and Linux capabilities can be injected into the template, leading to a privileged pod running on the target node with the host root filesystem mounted.
date: "2026-05-11T16:18:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - privilege-escalation
  - template-injection
vendors:
  - Rancher
  - SUSE
products:
  - local-path-provisioner (< 0.0.34)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1608
    technique_name: Stage Capabilities
references:
  - https://github.com/advisories/GHSA-7fxv-8wr2-mfc4
  - CVE-2026-44543
rules:
  - title: Detect Malicious HelperPod Template Modifications - Privileged Container
    description: Detects CVE-2026-44543 exploitation — modification of the local-path-config ConfigMap to inject a privileged container definition.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1608.001
    data_sources:
      - file_event
      - linux
  - title: Detect Malicious HelperPod Template Modifications - HostPath Mount
    description: Detects CVE-2026-44543 exploitation — detects modification of the `local-path-config` ConfigMap to inject a `hostPath` volume mount.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1608.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Rancher local-path-provisioner is vulnerable to a HelperPod template injection. A malicious user with the ability to modify the `local-path-config` ConfigMap in the `local-path-storage` namespace can manipulate the `helperPod.yaml` template. This template is used by the provisioner to create HelperPods during PersistentVolumeClaim (PVC) provisioning and cleanup. The vulnerability stems from insufficient validation of the `helperPod.yaml` template, which allows the injection of security-sensitive fields like `securityContext.privileged`, `hostPath` volumes, and Linux capabilities. Successfully exploiting this vulnerability can result in a privileged pod running on the target node with the host root filesystem mounted. Patched versions of `local-path-provisioner` include releases v0.0.34 and later. This issue is identified as CVE-2026-44543.

## Attack Chain

1. Attacker gains access to the Kubernetes cluster.
2. Attacker obtains permission to edit the `local-path-config` ConfigMap within the `local-path-storage` namespace.
3. Attacker modifies the `helperPod.yaml` template within the `local-path-config` ConfigMap to inject malicious configurations, such as setting `securityContext.privileged` to `true` or adding a `hostPath` volume mount.
4. Attacker triggers a PVC provisioning or cleanup operation, causing the `local-path-provisioner` to load the modified `helperPod.yaml` template.
5. The `local-path-provisioner` creates a HelperPod based on the attacker-controlled template.
6. The malicious HelperPod is deployed on a node within the cluster, inheriting the injected privileges, such as privileged access or a host root filesystem mount.
7. The attacker leverages the privileged HelperPod to access sensitive host files, read ServiceAccount tokens, or modify files on the host node.
8. The attacker escalates privileges and potentially compromises the entire node or cluster.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive host files, including ServiceAccount tokens from other pods residing on the same node. Attackers can also access other tenants' local-path volume data, potentially leading to data breaches and further lateral movement within the cluster. Modification of files on the host node can disrupt services and compromise the integrity of the system. The vulnerability, CVE-2026-44543, presents a significant risk to Kubernetes environments utilizing the Rancher local-path-provisioner.

## Recommendation

*   Upgrade to `local-path-provisioner` version v0.0.34 or later to incorporate the fix that validates the HelperPod template, mitigating the risk of injecting malicious configurations (reference: Patches section).
*   Restrict write access to the `local-path-config` ConfigMap in the `local-path-storage` namespace, ensuring that only trusted administrators can modify this ConfigMap (reference: Workarounds section).
*   Mark the ConfigMap as immutable after deployment to prevent unauthorized modifications (reference: Workarounds section and example `kubectl` command).
*   Enable Kubernetes Pod Security Admission (PSA) for the `local-path-storage` namespace, enforcing a security policy like `baseline` to prevent privileged HelperPods from being created, even if the template is altered (reference: Workarounds section and example `kubectl` command).
*   Monitor Kubernetes audit logs for modifications to the `local-path-config` ConfigMap in the `local-path-storage` namespace, alerting on unexpected changes.
