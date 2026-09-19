---
title: Unauthenticated SSRF and DoS in OpenShift Console
slug: 2026-09-openshift-api-vuln
description: An unauthenticated vulnerability in the OpenShift console /api/devfile/ endpoints allows remote attackers to perform Server-Side Request Forgery (SSRF) and cause Denial of Service (DoS) via memory exhaustion.
date: "2026-09-19T00:07:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:redhat:openshift:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud
  - web-application
vendors:
  - Red Hat
products:
  - OpenShift
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated access to the /api/devfile/ and /api/devfile/samples/ endpoints allows a remote attacker to send crafted devfile payloads.
    confidence_band: high
cves:
  - id: CVE-2026-75885
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75885
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review ingress/WAF logs for traffic targeting /api/devfile/ endpoints from unauthorized sources
      owner: SOC
      due: 24h
      evidence: CVE-2026-75885 allows unauthenticated access to specific endpoints
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security patches for OpenShift console to address CVE-2026-75885
      owner: IT Operations
      addresses: CVE-2026-75885
      evidence: NVD vulnerability disclosure
---

CVE-2026-75885 affects the OpenShift console, exposing internal services to unauthorized interaction and threatening service availability. The vulnerability resides in the improper validation of inputs provided to the `/api/devfile/` and `/api/devfile/samples/` endpoints. By submitting crafted devfile payloads, an unauthenticated remote attacker can force the console pod to perform requests against internal infrastructure, facilitating Server-Side Request Forgery (SSRF) and potentially exposing sensitive internal data through reflected responses. Furthermore, the absence of Content-Length header enforcement allows an attacker to stream large, unconstrained request bodies. This triggers uncontrolled memory allocation within the console pod, leading to pod instability and Denial of Service (DoS). This vulnerability is critical for organizations relying on OpenShift for container orchestration, as the console pod often possesses high-level access within the cluster environment.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to probe internal microservices or orchestrate a DoS condition on the OpenShift management layer. This can lead to the exfiltration of internal service metadata or the complete disruption of administrative console functions, affecting all teams relying on the platform for cluster management. The CVSS score of 9.3 reflects the high risk of unauthenticated remote compromise.

## Recommendation

- Monitor web server access logs for any unauthenticated POST requests targeting the `/api/devfile/` or `/api/devfile/samples/` paths.
- Implement network-level restrictions or Web Application Firewall (WAF) policies to block unauthenticated access to the OpenShift console management API.
- Ensure the OpenShift environment is updated to the latest vendor-provided patch releases that remediate CVE-2026-75885.
