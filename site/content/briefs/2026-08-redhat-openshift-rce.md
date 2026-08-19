---
title: Remote Code Execution Vulnerability in Red Hat OpenShift Container Platform
slug: 2026-08-redhat-openshift-rce
description: A critical remote code execution vulnerability, tracked as CVE-2024-8979, allows unauthenticated remote attackers to execute arbitrary code within the Red Hat OpenShift Container Platform environment.
date: "2026-08-19T10:31:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpdeveloper:essential_addons_for_elementor:*:*:*:*:lite:wordpress:*:*
tags:
  - vulnerability
  - cloud-security
  - rce
vendors:
  - Red Hat
products:
  - OpenShift Container Platform
cves:
  - id: CVE-2024-8979
    cvss: 8
    epss: 0.00493
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2028
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenShift Container Platform instances according to vendor guidance for CVE-2024-8979.
      owner: IT Operations
      due: 24h
      evidence: CVE-2024-8979
  mitigation_plan:
    - priority: immediate
      action: Patch affected software
      owner: IT Operations
      addresses: CVE-2024-8979
---

Red Hat has identified a critical vulnerability within the OpenShift Container Platform that enables a remote, unauthenticated attacker to achieve arbitrary code execution. This vulnerability, identified as CVE-2024-8979, represents a significant risk to the integrity and security of containerized environments managed by the platform. Attackers can leverage this flaw to bypass authentication mechanisms and execute commands directly on the platform infrastructure. Given the critical nature of the flaw and the potential for full system compromise, organizations running Red Hat OpenShift should immediately review vendor security advisories and apply available patches or configuration mitigations to secure their container orchestration clusters.

## Impact

Successful exploitation of this vulnerability results in full remote code execution on the affected Red Hat OpenShift nodes. This grants an attacker the ability to manipulate container workloads, access sensitive data residing in the cluster, and potentially move laterally within the organization's network. The scope of impact encompasses all organizations utilizing vulnerable versions of the OpenShift Container Platform.

## Recommendation

- Identify all Red Hat OpenShift Container Platform installations within the environment that are subject to the advisory for CVE-2024-8979.
- Apply security patches provided by Red Hat to remediate the vulnerability across all cluster nodes immediately.
- Monitor cluster logs and audit trails for unauthorized execution patterns or anomalous administrative commands that could indicate exploitation attempts.
