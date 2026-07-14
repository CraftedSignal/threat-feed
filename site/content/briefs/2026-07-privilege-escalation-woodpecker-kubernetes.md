---
title: Woodpecker Privilege Escalation via Unrestricted Kubernetes serviceAccountName
slug: 2026-07-privilege-escalation-woodpecker-kubernetes
description: A high-severity privilege escalation vulnerability (CVE-2026-61549) in Woodpecker CI, specifically affecting instances using the Kubernetes backend, allows any user with Push permissions on a connected repository to run pipeline pods under an arbitrary ServiceAccount, potentially leading to secret exfiltration and full cluster takeover.
date: "2026-07-14T20:33:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - kubernetes
  - ci/cd
  - vulnerability
vendors:
  - Woodpecker CI
products:
  - Woodpecker CI (v1.0.0 through v3.15.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: If a privileged ServiceAccount is reachable in that namespace, this can lead to secret exfiltration (database credentials, API keys, TLS certs)
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Resource Hijacking
    evidence: this can lead to [...] full cluster takeover.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-qf34-295c-26v8
  - https://github.com/woodpecker-ci/woodpecker/pull/6792
---

A high-severity privilege escalation vulnerability, tracked as CVE-2026-61549, affects Woodpecker CI instances configured with the Kubernetes backend. Identified in versions 1.0.0 through 3.15.0, this flaw allows an attacker to manipulate the `serviceAccountName` parameter within pipeline configurations. Specifically, a user possessing "Push" permissions on a repository connected to the CI instance can specify an arbitrary Kubernetes ServiceAccount to execute pipeline pods. This bypasses typical administrative controls and allows the pipeline pod to inherit the permissions of the chosen ServiceAccount, even if it is highly privileged. The vulnerability, introduced in commit `609ba481b5e912f59aaae8ca7bc22b44523c5e37`, opens the door to critical security risks. Defenders should be aware that successful exploitation could lead to unauthorized access to sensitive data, such as database credentials, API keys, and TLS certificates, ultimately facilitating full Kubernetes cluster takeover. Immediate patching or mitigation is crucial for all affected deployments.

## Attack Chain

1. Attacker gains "Push" permission to a repository connected to a vulnerable Woodpecker CI instance running the Kubernetes backend.
2. Attacker crafts a malicious pipeline configuration file (e.g., `.woodpecker/pipeline.yml`) within the repository.
3. The malicious pipeline configuration includes a `backend_options.kubernetes.serviceAccountName` parameter set to an arbitrary, privileged ServiceAccount existing in the Kubernetes pipeline namespace.
4. The attacker pushes the crafted pipeline configuration to the repository.
5. Woodpecker CI detects the push event and initiates a new pipeline run based on the updated configuration.
6. Woodpecker CI creates a Kubernetes pod to execute the pipeline steps, unrestrictedly using the attacker-specified `serviceAccountName` in the pod's specification.
7. The newly created pipeline pod executes with the full RBAC permissions associated with the privileged ServiceAccount defined by the attacker.
8. The attacker leverages these elevated privileges to exfiltrate sensitive data (e.g., credentials, API keys, TLS certs) or perform actions leading to full Kubernetes cluster compromise.

## Impact

This vulnerability allows for significant privilege escalation within a Kubernetes cluster. If successfully exploited, an attacker can gain the RBAC permissions of an arbitrary ServiceAccount, which can lead to the exfiltration of sensitive information such as database credentials, API keys, and TLS certificates. The ultimate consequence of exploitation is the potential for full Kubernetes cluster takeover, impacting all workloads and data within the cluster. Any organization operating a Woodpecker CI instance with the Kubernetes backend in versions 1.0.0 through 3.15.0 is vulnerable to these severe consequences.

## Recommendation

* Deploy the patched version of Woodpecker CI (`v3.16.0` or later) to address CVE-2026-61549 immediately.
* Restrict "Push" access on repositories connected to your Woodpecker CI instance (Woodpecker CI v1.0.0-v3.15.0) to trusted users only.
* Harden the Kubernetes pipeline namespace by ensuring no privileged ServiceAccounts exist or are bound within it, and keep the `default` ServiceAccount minimally privileged.
* Disable ServiceAccount token automounting for any ServiceAccounts that should not be used by Woodpecker CI pipelines.
* Enforce an admission policy (e.g., using OPA/Gatekeeper, Kyverno, or a ValidatingAdmissionPolicy) in Kubernetes to reject pipeline pods from Woodpecker CI (v1.0.0-v3.15.0) that attempt to set an unexpected `serviceAccountName`.
