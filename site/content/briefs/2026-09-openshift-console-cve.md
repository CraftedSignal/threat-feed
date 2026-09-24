---
title: Unauthenticated Information Disclosure in OpenShift Console via CatalogdHandler
slug: 2026-09-openshift-console-cve
description: A misconfiguration in the OpenShift Console CatalogdHandler allows unauthenticated remote attackers to leak internal operator-catalog data and relay requests into the catalogd namespace.
date: "2026-09-24T00:45:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:openshift_console:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud-native
  - identity-management
vendors:
  - Red Hat
products:
  - OpenShift Console
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can exploit a misconfiguration in the CatalogdHandler, which lacks proper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-75886
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75886
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review ingress access logs for unexpected access to catalogd API paths
      owner: SOC
      due: 24h
      evidence: Source document identifies the CatalogdHandler as the entry point for the exploit
  mitigation_plan:
    - priority: immediate
      action: Monitor Red Hat errata for the patched version of OpenShift Console addressing CVE-2026-75886
      owner: IT Operations
      addresses: CVE-2026-75886
---

CVE-2026-75886 affects the Red Hat OpenShift Console, specifically within the CatalogdHandler component. The vulnerability arises from a lack of mandatory authentication checks coupled with the improper forwarding of the `openshift-session-token` cookie. This configuration error enables an unauthenticated remote attacker to interact directly with the in-cluster catalogd service. By successfully leveraging this flaw, an attacker can exfiltrate sensitive internal operator-catalog index information. Furthermore, the vulnerability provides a relay vector into the `openshift-catalogd` namespace, potentially exposing cluster-internal services that are intended to be shielded from external access. This is a critical risk for organizations relying on OpenShift for container orchestration, as it facilitates unauthorized reconnaissance and potential lateral movement into internal cluster management components.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized access to internal operator-catalog index information. Beyond the disclosure of sensitive infrastructure metadata, the ability to relay requests into the `openshift-catalogd` namespace may allow an attacker to reach or interact with other internal cluster-catalog components that lack secondary authentication, potentially escalating access within the internal network segment.

## Recommendation

- Monitor web application logs for unauthorized POST or GET requests to catalog-related API endpoints originating from outside the cluster internal network.
- Review cluster ingress and network policy configurations to limit access to the OpenShift Console and ensure that internal services like catalogd are not exposed to external traffic.
- Update OpenShift Console to the latest patched version provided by Red Hat as soon as the security advisory for CVE-2026-75886 is released.
