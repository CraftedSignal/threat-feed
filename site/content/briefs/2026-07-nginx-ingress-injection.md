---
title: NGINX Ingress Controller Injection Vulnerability via CRDs/Annotations (CVE-2026-55723)
slug: 2026-07-nginx-ingress-injection
description: An injection vulnerability exists in the NGINX Ingress Controller when configured with Custom Resource Definitions (CRDs) or Ingress annotations. An authenticated attacker with write permissions to these CRDs or annotations via the Kubernetes API can craft values to inject arbitrary NGINX configuration directives. This can lead to creating or deleting files and disabling services, affecting the control plane without exposing the data plane.
date: "2026-07-15T15:23:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - vulnerability
  - injection
  - webserver
  - cve
vendors:
  - NGINX
products:
  - NGINX Ingress Controller
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Impact: ... disable services.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An authenticated attacker ... may craft values that inject arbitrary NGINX configuration directives.
    confidence_band: high
cves:
  - id: CVE-2026-55723
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55723
---

A critical injection vulnerability, identified as CVE-2026-55723, has been discovered in the NGINX Ingress Controller. This vulnerability affects installations configured with Custom Resource Definitions (CRDs) or Ingress annotations. The flaw resides in the configuration generator, where multiple user-controllable fields are written into the generated NGINX configuration without proper sanitization. An authenticated attacker who possesses write access to these NGINX Ingress Controller CRDs or Ingress annotations via the Kubernetes API can exploit this by crafting malicious values to inject arbitrary NGINX configuration directives. Successful exploitation can lead to severe control plane compromises, including the creation or deletion of files and the disabling of services, though it does not expose the data plane. The CVSS v3.1 Base Score for this vulnerability is 8.3, categorizing it as high severity.

## Attack Chain

1. An authenticated attacker obtains write access to NGINX Ingress Controller Custom Resource Definitions (CRDs) or Ingress annotations via the Kubernetes API.
2. The attacker crafts malicious values containing arbitrary NGINX configuration directives intended for injection.
3. The attacker injects these crafted values into susceptible CRD fields or Ingress annotations.
4. The NGINX Ingress Controller's configuration generator processes the attacker-controlled input.
5. Due to the lack of sanitization, the injected NGINX configuration directives are written directly into the generated NGINX configuration.
6. The NGINX Ingress Controller reloads its configuration, applying the malicious directives.
7. The arbitrary directives are executed, leading to actions such as creating or deleting files or disabling services on the control plane.

## Impact

Successful exploitation of CVE-2026-55723 allows an authenticated attacker with write permissions to NGINX Ingress Controller CRDs or Ingress annotations to inject arbitrary NGINX configuration directives. This can result in the ability to create or delete arbitrary files on the system or disable critical services, leading to a denial of service or unauthorized modification of the Kubernetes cluster's control plane components related to NGINX Ingress. The vulnerability is isolated to the control plane, meaning the data plane traffic itself is not directly exposed or compromised.

## Recommendation

* **Patch CVE-2026-55723 immediately** on all affected NGINX Ingress Controller instances.
* Implement **least privilege access controls** for Kubernetes users and service accounts to NGINX Ingress Controller CRDs and Ingress annotations to minimize the attack surface.
* **Monitor Kubernetes API server logs** for unusual write operations or modifications to NGINX Ingress Controller CRDs or Ingress objects, especially from accounts that are not typically involved in such changes.
* **Regularly audit NGINX configuration files** for unexpected or unauthorized directives that could indicate compromise stemming from CVE-2026-55723.
