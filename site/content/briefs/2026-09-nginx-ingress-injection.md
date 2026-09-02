---
title: CVE-2026-77180 - NGINX Ingress Controller Configuration Injection
slug: 2026-09-nginx-ingress-injection
description: Authenticated attackers can exploit an injection vulnerability in the NGINX Ingress Controller for Kubernetes by injecting arbitrary configuration directives via Ingress annotations.
date: "2026-09-02T17:15:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubernetes:nginx_ingress_controller:*:*:*:*:*:*:*:*
vendors:
  - Kubernetes
products:
  - NGINX Ingress Controller
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: An authenticated attacker with permission to create or modify these annotations may craft values that inject arbitrary NGINX configuration directives.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated attacker granted write access to NGINX Ingress Controller Ingress annotations through the Kubernetes API may be able to inject arbitrary NGINX configuration directives.
    confidence_band: high
cves:
  - id: CVE-2026-77180
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77180
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Engineering
  immediate_actions:
    - action: Review and audit RBAC permissions for Ingress object creation cluster-wide.
      owner: Infrastructure Engineering
      due: 48h
      evidence: This is a control plane issue requiring write access to annotations.
  mitigation_plan:
    - priority: immediate
      action: Upgrade NGINX Ingress Controller to the latest vendor-provided patched version.
      owner: IT Operations
      addresses: CVE-2026-77180
---

CVE-2026-77180 represents a security vulnerability in the NGINX Ingress Controller for Kubernetes, arising from improper sanitization of Ingress annotations during the configuration generation process. An authenticated attacker who possesses the necessary privileges to create or update Kubernetes Ingress objects can supply malicious input within specific annotation fields. These inputs are subsequently incorporated into the generated NGINX configuration files without adequate validation, effectively allowing the attacker to inject arbitrary NGINX directives. 

This issue is classified as a control plane vulnerability rather than a data plane exposure, meaning the impact is limited to the configuration logic of the ingress controller itself. Successful exploitation enables an attacker to manipulate server behavior, which may lead to service disruption, unauthorized modification of the NGINX configuration, or potential interaction with the underlying filesystem depending on the injected directives. Defenders should note that this vulnerability requires prior authorization within the Kubernetes cluster, making it an escalation or misuse path rather than a simple unauthenticated remote code execution.

## Impact

The vulnerability allows for the modification of the NGINX Ingress Controller configuration, which can lead to service denial, arbitrary file system manipulation, or unauthorized changes to traffic routing rules within the cluster. Because it affects the control plane of the Kubernetes Ingress mechanism, the scope of impact is potentially cluster-wide for environments where users are granted broad permissions to manage Ingress resources.

## Recommendation

- Implement strict Kubernetes RBAC policies to limit which users or service accounts have permission to create or update Ingress objects.
- Apply Admission Controllers or Validating Webhooks to sanitize or reject Ingress annotations containing suspicious characters (e.g., newline characters, semicolon delimiters, or unauthorized directive keywords).
- Update NGINX Ingress Controller to the latest security-patched release provided by the vendor.
- Review current Ingress configurations for unusual or non-standard annotation usage using the Kubernetes API audit logs.
