---
title: SSRF Vulnerability in KubeSphere Git Credential Verification
slug: 2026-09-kubesphere-ssrf
description: KubeSphere versions up to 4.1.3 contain a server-side request forgery (SSRF) vulnerability in the git credential verification endpoint, allowing authenticated attackers to exfiltrate Kubernetes Secrets.
date: "2026-09-15T13:40:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubesphere:kubesphere:*:*:*:*:*:*:*:*
vendors:
  - KubeSphere
products:
  - KubeSphere (<= 4.1.3)
cves:
  - id: CVE-2026-91923
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91923
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade KubeSphere to a version after 4.1.3
      owner: IT Operations
      due: 72h
      evidence: Source identifies 4.1.3 as affected
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from KubeSphere API pods using network policies
      owner: IT Operations
      addresses: CVE-2026-91923
      evidence: Mitigates SSRF network reachability
---

KubeSphere versions through 4.1.3 contain a server-side request forgery (SSRF) vulnerability located within the platform's git credential verification endpoint. The vulnerability arises because the endpoint fails to enforce allowlist restrictions on user-supplied URLs. An authenticated attacker can exploit this flaw to force the KubeSphere server to make unauthorized requests to internal network services. By manipulating the input and observing the subsequent error response handling, an attacker can exfiltrate basic-authentication credentials associated with Kubernetes Secrets located in any namespace within the cluster. This vulnerability, tracked as CVE-2026-91923, poses a significant risk to cluster integrity and sensitive data, as it allows for the escalation of privileges through the unauthorized access and retrieval of internal configuration and credential data.

## Impact

Successful exploitation of this SSRF vulnerability allows an authenticated attacker to bypass intended network boundaries and access sensitive information, including basic-auth credentials stored within Kubernetes Secrets. This facilitates lateral movement and potentially full cluster compromise, as these secrets may contain keys for other services, databases, or third-party integrations.

## Recommendation

* Upgrade KubeSphere to a version beyond 4.1.3 to remediate CVE-2026-91923.
* Audit access logs for the KubeSphere git credential verification endpoint to identify anomalous requests containing internal IP ranges or sensitive ports.
* Apply network policies to restrict egress traffic from the KubeSphere controller/API pod to only required external endpoints, preventing internal network scanning.
