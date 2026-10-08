---
title: Multiple Vulnerabilities in Argo CD
slug: 2026-10-argo-cd-vulnerabilities
description: Argo CD is affected by multiple vulnerabilities including CVE-2024-28113, CVE-2024-28114, CVE-2024-28115, and CVE-2024-28116, which allow for remote code execution, unauthorized information disclosure, and security control bypasses.
date: "2026-10-08T19:20:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:peering-manager:peering_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:o:amazon:freertos:*:*:*:*:*:*:*:*
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud
  - kubernetes
vendors:
  - Argo Project
products:
  - Argo CD (<= 10.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit multiple vulnerabilities in Argo CD.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit multiple vulnerabilities in Argo CD to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2024-28113
    cvss: 3.5
    epss: 0.00406
  - id: CVE-2024-28114
    cvss: 8.1
    epss: 0.0133
  - id: CVE-2024-28115
    cvss: 8.8
    epss: 0.0024
  - id: CVE-2024-28116
    cvss: 8.8
    epss: 0.0576
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3802
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Argo CD to 1.7.45 or later
      owner: IT Operations
      addresses: CVE-2024-28113, CVE-2024-28114, CVE-2024-28115, CVE-2024-28116
      evidence: Source advisory identifies multiple vulnerabilities in Argo CD.
---

Argo CD, a popular continuous delivery tool for Kubernetes, is impacted by a set of critical vulnerabilities identified as CVE-2024-28113, CVE-2024-28114, CVE-2024-28115, and CVE-2024-28116. These flaws collectively enable unauthenticated or authenticated remote attackers to achieve remote code execution, exfiltrate sensitive configuration data and credentials, bypass existing access control mechanisms, or perform denial of service attacks against the infrastructure.

Given that Argo CD frequently operates with administrative privileges within a Kubernetes cluster to manage deployments, successful exploitation of these vulnerabilities compromises the security posture of the entire target cluster. Security teams should prioritize patching affected instances to prevent attackers from hijacking continuous deployment workflows or extracting secrets stored within Argo CD configuration.

## Impact

Successful exploitation of these vulnerabilities allows for full compromise of the Argo CD instance. Attackers can gain code execution, access sensitive Kubernetes secrets or environment variables, and modify delivery pipelines to propagate malicious payloads to production environments. This impact is significant for organizations relying on GitOps workflows, as the integrity of the entire software supply chain is at risk.

## Recommendation

Prioritize patching all internet-facing and internal Argo CD deployments to the latest secure version provided by the Argo Project. Verify that access to the Argo CD API and management interface is restricted to authorized administrative users only. Implement egress filtering for the Argo CD pod to prevent unauthorized connections to external C2 infrastructure in the event of partial compromise.
