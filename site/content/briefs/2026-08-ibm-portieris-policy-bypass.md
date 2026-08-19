---
title: IBM Portieris Image Policy Enforcement Bypass
slug: 2026-08-ibm-portieris-policy-bypass
description: IBM Portieris versions 0.5.0 through 0.14.2 contain a missing authorization vulnerability that allows authenticated attackers to bypass image policy enforcement by manipulating pod owner references.
date: "2026-08-19T22:39:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - kubernetes
  - ibm
  - security-policy
vendors:
  - IBM
products:
  - Portieris (0.5.0-0.14.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM Portieris 0.5.0 through 0.14.2 could allow a remote authenticated attacker to bypass image policy enforcement due to improper authorization of pod owner references.
    confidence_band: high
cves:
  - id: CVE-2026-18544
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18544
  - https://www.ibm.com/support/pages/node/7284125
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch IBM Portieris to the latest supported version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-18544 official remediation
  mitigation_plan:
    - priority: immediate
      action: Review Kubernetes RBAC for users with permission to create or update pods
      owner: Security Engineering
      addresses: CVE-2026-18544
      evidence: Source support
---

IBM Portieris, an admission controller for Kubernetes designed to enforce image security policies, contains a vulnerability (CVE-2026-18544) in versions 0.5.0 through 0.14.2. This flaw stems from improper authorization of pod owner references, classified under CWE-862 (Missing Authorization). 

The vulnerability allows a remote authenticated user with access to the cluster to circumvent configured image security policies. By manipulating the pod owner references during deployment requests, an attacker can trick the admission controller into bypassing checks that would normally prevent the execution of unauthorized or non-compliant container images. This effectively neutralizes the security controls intended to ensure only verified, trusted images are run within the Kubernetes environment, potentially allowing the execution of malicious or vulnerable code.

## Impact

The vulnerability carries a CVSS 3.1 base score of 8.1, reflecting its high impact on confidentiality and integrity. If successfully exploited, an attacker could deploy arbitrary images that violate organizational security posture, facilitating unauthorized access or persistence within the containerized infrastructure.

## Recommendation

* Apply the security update provided by IBM in the official support bulletin to address CVE-2026-18544.
* Audit existing Kubernetes admission controller configurations to ensure that pod owner references are strictly validated.
* Monitor Kubernetes audit logs for suspicious or unauthorized image deployment attempts that bypass expected policy enforcement.
* Ensure Kubernetes RBAC is restricted to limit the ability of authenticated users to modify pod specifications or influence pod owner references.
