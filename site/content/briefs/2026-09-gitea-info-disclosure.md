---
title: Information Disclosure Vulnerability in Gitea
slug: 2026-09-gitea-info-disclosure
description: A vulnerability in Gitea allows a remote, unauthenticated attacker to exploit an information disclosure flaw, potentially exposing sensitive repository or system data.
date: "2026-09-24T14:00:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Gitea
products:
  - Gitea (< 1.22.6)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability in Gitea allows a remote, unauthenticated attacker to exploit an information disclosure flaw, potentially exposing sensitive repository or system data.
    confidence_band: high
cves:
  - id: CVE-2024-52292
    cvss: 7.7
    epss: 0.00746
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3543
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Gitea to version 1.22.6 or later
      owner: IT Operations
      addresses: CVE-2024-52292
      evidence: Source advisory specifies Gitea versions prior to 1.22.6 are vulnerable
---

A security vulnerability exists in Gitea versions prior to 1.22.6, which permits a remote, unauthenticated attacker to perform information disclosure. This flaw enables unauthorized access to repository data or internal system information that should otherwise be restricted. Defenders should prioritize patching to Gitea version 1.22.6 or later to mitigate the risk of data leakage.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to access sensitive internal data, potentially leading to the exposure of proprietary source code, credentials, or metadata stored within the Gitea instance. The scope of impact affects any organization hosting Gitea instances vulnerable to this specific information disclosure flaw.

## Recommendation

* Patch Gitea to version 1.22.6 or later immediately.
* Audit access logs for unusual patterns of unauthenticated requests targeting repository metadata or configuration endpoints.
