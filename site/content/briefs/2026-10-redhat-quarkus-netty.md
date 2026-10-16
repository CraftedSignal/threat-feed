---
title: Multiple Vulnerabilities in Red Hat OpenShift and Enterprise Linux Quarkus/Netty Components
slug: 2026-10-redhat-quarkus-netty
description: Multiple vulnerabilities in Red Hat OpenShift and RHEL, involving Quarkus and Netty components, enable remote attackers to perform information disclosure or trigger denial-of-service conditions.
date: "2026-10-16T16:27:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - OpenShift
  - Enterprise Linux
affected_os:
  - RHEL
cves:
  - id: CVE-2024-47754
    cvss: 5.5
    epss: 0.00209
  - id: CVE-2024-47755
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2024-1068
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit RHEL and OpenShift infrastructure for affected Quarkus/Netty versions
      owner: IT Operations
      due: 48h
      evidence: Source document identifies vulnerabilities in Quarkus and Netty components
  mitigation_plan:
    - priority: immediate
      action: Apply patches for CVE-2024-47754 and CVE-2024-47755
      owner: IT Operations
      addresses: CVE-2024-47754, CVE-2024-47755
      evidence: BSI vulnerability disclosure
---

Red Hat has identified multiple security vulnerabilities impacting Red Hat OpenShift and Red Hat Enterprise Linux (RHEL) systems, specifically targeting the Quarkus and Netty components. These flaws, tracked as CVE-2024-47754 and CVE-2024-47755, expose affected environments to remote exploitation. Successful exploitation by an unauthenticated attacker can lead to the unauthorized disclosure of sensitive system information or result in a denial-of-service (DoS) state, causing service degradation or total unavailability. Given the integration of Quarkus and Netty in various containerized and cloud-native application stacks within the Red Hat ecosystem, these vulnerabilities pose a significant risk to the stability and confidentiality of enterprise infrastructure. Organizations running these Red Hat products should prioritize vulnerability assessments to identify affected components and apply the security patches provided by Red Hat to remediate these risks.

## Impact

Successful exploitation may lead to unauthorized access to system information or service disruptions across targeted enterprise infrastructure. These vulnerabilities impact critical enterprise platforms, including Red Hat OpenShift and RHEL, potentially affecting high-availability services and containerized workloads. If left unpatched, the denial-of-service condition can result in unplanned downtime for production applications relying on these integrated components.

## Recommendation

- Perform a comprehensive audit of Red Hat OpenShift and RHEL environments to identify components utilizing vulnerable versions of Quarkus and Netty.
- Apply security updates for CVE-2024-47754 and CVE-2024-47755 provided by Red Hat through the official Red Hat portal immediately.
- Monitor logs for unusual error rates or spikes in service interruptions associated with Quarkus-based applications that may indicate attempted denial-of-service exploitation.
