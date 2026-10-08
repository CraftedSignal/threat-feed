---
title: Excessive RBAC Permissions in Red Hat OpenShift insights-operator
slug: 2026-10-openshift-insights-rbac
description: A misconfiguration in the OpenShift insights-operator ClusterRole grants the 'gather' service account cluster-wide read access to secrets, enabling privilege escalation for attackers who can spawn pods with that identity.
date: "2026-10-08T17:14:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:openshift_container_platform:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - OpenShift Container Platform
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker capable of spawning a pod mounted with the 'gather' service account can exploit these elevated privileges to perform unauthorized exfiltration of sensitive secret data.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The insights-operator-gather ClusterRole grants the operator's service account read access to secrets in the core API group.
    confidence_band: high
cves:
  - id: CVE-2026-93017
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93017
  - https://github.com/openshift/insights-operator/blob/8f15e3157ff09f54ab22801f5b21da35a195cc6d/manifests/03-clusterrole.yaml#L368-L373
action_plan:
  priority: elevated
  owners:
    - SOC
    - Platform Engineering
  immediate_actions:
    - action: Review and restrict RBAC for the insights-operator-gather ClusterRole.
      owner: Platform Engineering
      due: 48h
      evidence: CVE-2026-93017
  hunt_leads:
    - lead: 'Identify pods using serviceAccountName: gather'
      technique_id: T1068
      data_needed:
        - Kubernetes Audit Logs or cluster resource manifests
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of the serviceAccountName usage.
  mitigation_plan:
    - priority: immediate
      action: Patch OpenShift Container Platform according to Red Hat guidance.
      owner: Platform Engineering
      addresses: CVE-2026-93017
      evidence: NVD vulnerability disclosure.
---

Red Hat OpenShift Container Platform is impacted by a critical privilege escalation vulnerability (CVE-2026-93017) stemming from an overly permissive ClusterRole assigned to the `insights-operator`. The `insights-operator-gather` ClusterRole incorrectly grants the `gather` service account `get` and `list` permissions for `secrets` in the core API group, without limiting the scope to specific namespaces or resources. This effectively permits the service account to access every secret across the entire cluster.

An attacker who has gained the ability to create pods or influence pod specifications - for instance, through a compromised developer account or an application-layer injection vulnerability - can mount the `gather` service account to an attacker-controlled pod. Once the pod is running with this identity, the attacker can use standard Kubernetes API calls to retrieve secrets, such as API keys, database credentials, or TLS certificates, leading to a complete compromise of sensitive information stored within the cluster.

## Attack Chain

1. Attacker identifies a vulnerability (e.g., remote code execution or unauthorized access) allowing pod creation or modification within the cluster.
2. Attacker crafts a malicious pod specification that mounts the `gather` service account using `serviceAccountName: "gather"`.
3. Attacker deploys the malicious pod into the cluster via the API server.
4. The pod executes, gaining the elevated permissions associated with the `gather` service account.
5. Attacker executes `kubectl get secrets --all-namespaces` or makes equivalent API requests from within the pod.
6. The Kubernetes API server grants the request due to the over-privileged ClusterRole.
7. Attacker exfiltrates gathered secrets to external infrastructure to achieve final objectives.

## Impact

Successful exploitation results in full exposure of cluster-wide secrets, including but not limited to database credentials, service-to-service authentication tokens, and TLS private keys. This can facilitate lateral movement within the cluster, escalation to other services, and access to external resources secured by the compromised credentials.

## Recommendation

1. Review the current cluster-wide RBAC policies for the `insights-operator` and restrict the scope of the `insights-operator-gather` role to only those namespaces and resources strictly necessary for its telemetry-gathering function.
2. Implement Kubernetes Admission Controllers or Policy-as-Code (such as OPA Gatekeeper or Kyverno) to prevent the arbitrary mounting of sensitive service accounts by user-defined pods.
3. Audit existing pods and service account bindings to identify unauthorized use of the `gather` service account.
4. Monitor cluster API audit logs for suspicious `get` or `list` requests on `secrets` resources originating from the `gather` service account.
