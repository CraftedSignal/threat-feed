---
title: Kubernetes Client Certificate Signing Request Created or Approved by Non-System Identity
slug: 2026-05-kubernetes-csr-persistence
description: Detects creation or approval of a Kubernetes CertificateSigningRequest (CSR) by a non-system identity, indicating an attacker attempting to obtain a long-lived client certificate for persistent cluster access with elevated privileges.
date: "2026-05-14T12:52:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - persistence
  - privilege-escalation
vendors:
  - kubernetes
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/
  - https://attack.mitre.org/techniques/T1098/
rules:
  - title: Kubernetes Client Certificate Signing Request Created or Approved
    description: Detects creation or approval of a Kubernetes CertificateSigningRequest (CSR) by a non-system identity, which could indicate an attacker is attempting to obtain a long-lived client certificate for persistent access to the cluster with elevated privileges.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - audit
      - kubernetes
  - title: Kubernetes CSR Request for System Masters Group
    description: Detects a CertificateSigningRequest (CSR) containing the system:masters group in the encoded request.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - audit
      - kubernetes
  - title: Kubernetes CSR Request for Kube Controller Manager Identity
    description: Detects a CertificateSigningRequest (CSR) containing the system:kube-controller-manager identity in the encoded request.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - audit
      - kubernetes
rules_count: 3
---

This detection rule identifies the creation or approval of Kubernetes CertificateSigningRequests (CSRs) by identities outside the expected system accounts. Attackers who have compromised a Kubernetes cluster can exploit this by submitting a CSR with a privileged Common Name (CN), such as system:kube-controller-manager or system:masters, and subsequently approving it. This grants them a long-lived client certificate.  Unlike short-lived service account tokens, these certificates remain valid until expiration or cluster CA rotation, ensuring persistent access. In non-EKS environments, the signed certificate allows authentication as a privileged entity from any location, bypassing the need for cluster network access, establishing a durable backdoor. This rule is designed to detect the abuse of CSRs for persistence and privilege escalation in Kubernetes environments.

## Attack Chain

1.  Attacker gains initial access to the Kubernetes cluster through compromised credentials or a vulnerability.
2.  Attacker identifies a privileged Common Name (CN), such as `system:masters` or `system:kube-controller-manager`.
3.  Attacker crafts a CertificateSigningRequest (CSR) with the chosen privileged CN. The CSR is encoded in base64.
4.  Attacker submits the CSR to the Kubernetes API server using `kubectl create csr`.
5.  Attacker attempts to approve the CSR using `kubectl certificate approve <csr-name>`.
6.  If RBAC permissions are misconfigured, the attacker successfully approves their own CSR.
7.  The Kubernetes API server signs the CSR, creating a client certificate.
8.  Attacker uses the client certificate to authenticate as the privileged identity and access cluster resources.

## Impact

A successful attack allows an attacker to gain persistent, privileged access to the Kubernetes cluster. This can lead to complete control over the cluster, allowing them to deploy malicious applications, steal sensitive data, or disrupt services. The long-lived nature of the client certificate makes it a highly effective backdoor, as it persists through pod restarts, token revocations, and even RBAC changes. The impact is especially severe in non-EKS environments, where the attacker can authenticate from anywhere without needing cluster network access.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Client Certificate Signing Request Created or Approved` to detect unauthorized CSR creation or approval events.
*   Review and harden RBAC configurations to prevent non-system identities from creating, updating, patching, or approving CertificateSigningRequests.
*   Enforce signer restrictions and approved issuers where supported to limit the signers used for CSRs.
*   Monitor Kubernetes audit logs for `create`, `update`, or `patch` events related to `certificatesigningrequests` where the user is not a system account, as defined in the rule's `user.name` exclusion list.
*   Investigate any alerts generated by the Sigma rule by extracting the Certificate Common Name from the base64-encoded request in `kubernetes.audit.requestObject.spec.request`, as described in the rule's notes.
*   If malicious activity is confirmed, deny further approval, delete or deny the CSR, revoke or rotate cluster signing trust if the CA or signer was abused, and invalidate issued credentials.
