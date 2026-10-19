---
title: SAML Authentication Replay Vulnerability in Red Hat Advanced Cluster Security
slug: 2026-10-rhacs-saml-replay
description: Red Hat Advanced Cluster Security for Kubernetes contains a SAML authentication flaw allowing attackers to replay unexpired assertions to obtain multiple valid session tokens.
date: "2026-10-19T14:09:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:advanced_cluster_security_for_kubernetes:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-security
  - saml
  - authentication-bypass
vendors:
  - Red Hat
products:
  - Advanced Cluster Security for Kubernetes
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: 'Use Alternate Authentication Material: Application Access Token'
    evidence: The Central SAML authentication ACS endpoint does not retain used SAML assertion or response identifiers to prevent replay.
    confidence_band: high
cves:
  - id: CVE-2026-103314
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103314
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all RHACS deployments and monitor Red Hat advisory channels for the remediation patch for CVE-2026-103314
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-103314 requires vendor patching
  mitigation_plan:
    - priority: immediate
      action: Shorten SAML assertion validity periods to reduce the window of opportunity for replay attacks
      owner: IT Operations
      addresses: CVE-2026-103314
      evidence: Reduces the time frame during which intercepted SAML assertions remain valid
---

A vulnerability, tracked as CVE-2026-103314, exists in Red Hat Advanced Cluster Security (RHACS) for Kubernetes regarding the Central component's SAML authentication process. The issue stems from the failure of the SAML assertion endpoint to properly track or invalidate SAML assertion and response identifiers once they have been processed. Consequently, an attacker who manages to intercept a legitimate, unexpired signed SAML response can successfully replay that response against the Central authentication endpoint multiple times. This leads to the generation of distinct and valid Central authentication tokens for the targeted identity. This vulnerability poses a significant risk to organizational access control, potentially enabling unauthorized persistent access to the Kubernetes security management plane.

## Impact

Successful exploitation of this flaw allows an attacker to bypass authentication controls by reusing valid session artifacts. If an attacker gains access to an authenticated SAML response, they can generate multiple valid sessions, effectively extending their access window or escalating privileges by impersonating the identity associated with the captured assertion. This affects the security integrity of the RHACS Central service, which is critical for enforcing security policies across managed Kubernetes clusters.

## Recommendation

Prioritize the identification of Red Hat Advanced Cluster Security instances within the environment. Monitor the vendor advisory portal for the release of security patches addressing CVE-2026-103314 and schedule an immediate upgrade to the patched version once available. Given the nature of the vulnerability, implement strict network-level controls and mTLS for communication paths involving the Central authentication endpoint to reduce the likelihood of SAML assertion interception. Review SAML configuration settings to minimize the validity window of assertions, reducing the time frame during which an intercepted assertion could be replayed.
