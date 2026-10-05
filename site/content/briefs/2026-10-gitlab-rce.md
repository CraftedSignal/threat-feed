---
title: Remote Code Execution Vulnerability in GitLab AI Gateway
slug: 2026-10-gitlab-rce
description: A critical remote code execution vulnerability (CVE-2026-90970) in GitLab AI Gateway allows unauthenticated attackers to execute arbitrary code on affected installations.
date: "2026-10-05T18:41:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gitlab:ai_gateway:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - webserver
  - gitlab
vendors:
  - GitLab
products:
  - AI Gateway (19.3.x < 19.3.2)
  - AI Gateway (19.4.x < 19.4.1)
  - AI Gateway (>= 18.1.6 and < 19.2.4)
cves:
  - id: CVE-2026-90970
    cvss: 9.9
    epss: 0.00943
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1262/
  - https://docs.gitlab.com/releases/patches/other-patches/patch-release-gitlab-ai-gateway-19-4-1-released/
  - https://www.cve.org/CVERecord?id=CVE-2026-90970
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch AI Gateway to 19.2.4 or later
      owner: IT Operations
      due: 24h
      evidence: GitLab Security Bulletin dated 2026-10-02
  mitigation_plan:
    - priority: immediate
      action: Upgrade AI Gateway to 19.2.4 or later
      owner: IT Operations
      addresses: CVE-2026-90970
---

A vulnerability identified as CVE-2026-90970 affects multiple versions of the GitLab AI Gateway. This flaw allows an unauthenticated remote attacker to achieve arbitrary code execution on the underlying host. The vulnerability is present in versions 19.3.x prior to 19.3.2, versions 19.4.x prior to 19.4.1, and versions 18.1.6 through 19.2.4. GitLab released security patches on October 2, 2026, to address this flaw. Organizations running AI Gateway components should prioritize patching to the latest safe versions to mitigate the risk of full system compromise.

## Impact

Successful exploitation allows an unauthenticated attacker to gain remote code execution capabilities on the GitLab AI Gateway server. This can lead to complete system takeover, unauthorized access to sensitive data processed by the AI Gateway, or lateral movement within the network environment.

## Recommendation

Prioritize patching all affected GitLab AI Gateway instances to the versions specified in the official GitLab security bulletin. Ensure that internet-facing instances are monitored for anomalous outbound traffic or unexpected child process execution from the AI Gateway service account.
