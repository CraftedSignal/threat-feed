---
title: Unauthenticated API Access in TrustyAI Service
slug: 2026-08-trustyai-auth-bypass
description: A vulnerability in the TrustyAI Service (TAS) deployment allows pods within the same cluster network to bypass authentication, enabling unauthorized read and write access to the backend API.
date: "2026-08-10T23:36:55Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TrustyAI
products:
  - TrustyAI Service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This vulnerability allows any pod on the cluster network to bypass authentication and directly access the TAS backend API.
    confidence_band: high
cves:
  - id: CVE-2026-15581
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15581
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Implement restrictive NetworkPolicies for TAS backend pods
      owner: IT Operations
      due: 48h
      evidence: Source identifies cross-pod network vulnerability
  mitigation_plan:
    - priority: immediate
      action: Enforce mTLS or application-level authentication for all internal service communication
      owner: IT Operations
      addresses: CVE-2026-15581
      evidence: Vulnerability allows bypass of standard authentication
---

A security vulnerability exists within the TrustyAI Service (TAS) deployment configuration that permits unauthenticated access to the backend API from other pods within the same Kubernetes cluster network. This flaw bypasses necessary authentication controls, granting any attacker-controlled or compromised pod the ability to interact with the TAS API directly. The impact is significant, as an adversary can read, tamper with, or delete sensitive monitoring data and service configurations. Furthermore, the ability to inject arbitrary data into the service enables potential disruption of tenant operations and data integrity compromise. Given the internal nature of the threat, this vulnerability is most relevant to environments hosting multi-tenant AI pipelines where network segmentation between workloads is not strictly enforced via NetworkPolicies.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain unauthorized control over the TrustyAI Service backend. This leads to the exposure of confidential monitoring data, the corruption of service configurations, and the potential for persistent disruption of tenant operations through data injection. Organizations using TAS in shared-tenant environments face the highest risk of lateral movement and service sabotage.

## Recommendation

- Implement Kubernetes NetworkPolicies to strictly restrict traffic to the TrustyAI Service backend API, ensuring only authorized pods can communicate with it.
- Review cluster-level ingress and service-mesh configurations to verify that authentication is enforced at the application layer for all TAS endpoints.
- Patch the affected TrustyAI Service deployment to the version addressing CVE-2026-15581 as soon as the vendor provides the update.
- Monitor logs for unauthorized API access attempts originating from internal cluster service IPs that do not correspond to known, authorized service consumers.
