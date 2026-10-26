---
brief_id: brief-2026-10-26-citrix-xenserver-bypass
event_id: brief-2026-10-26-citrix-xenserver-bypass
revision: 1
activity_at: "2026-10-26T22:20:35Z"
title: 'Citrix XenServer: Security policy bypass (CVE-2026-114406)'
slug: 2026-10-citrix-xenserver-bypass
description: A security policy bypass vulnerability in Citrix XenServer versions 8.4 and 9 allows attackers to circumvent established security controls, as detailed in Citrix bulletin CTX697257.
date: "2026-10-26T22:20:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: verified against source
cpes:
  - cpe:2.3:a:citrix:xenserver:8.4:*:*:*:*:*:*:*
  - cpe:2.3:a:citrix:xenserver:9:*:*:*:*:*:*:*
tags:
  - virtualization
  - security-update
  - vulnerability
vendors:
  - Citrix
products:
  - XenServer (8.4, 9)
cves:
  - id: CVE-2026-114406
    cvss: 6.8
    epss: 0.0031
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1384/
  - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697257&articleURL=XenServer_Security_Update_for_CVE_2026_114406
  - https://www.cve.org/CVERecord?id=CVE-2026-114406
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Apply security updates as detailed in Citrix bulletin CTX697257 to all XenServer 8.4 and 9 instances.
      owner: IT Operations
      addresses: CVE-2026-114406
      evidence: Se référer au bulletin de sécurité de l'éditeur pour l'obtention des correctifs.
---

A security policy bypass vulnerability exists in Citrix XenServer versions 8.4 and 9. This vulnerability, tracked as CVE-2026-114406, allows an attacker to circumvent security controls configured within the virtualization environment. Citrix has released security updates to address this flaw; users should refer to bulletin CTX697257 for remediation.

## Recommendation
- Inventory all internal deployments of Citrix XenServer 8.4 and 9 to identify instances requiring updates.
- Patch affected XenServer instances immediately by applying the security updates documented in Citrix bulletin CTX697257.
- Restrict administrative access to the XenServer management interfaces to authorized networks only, pending the application of patches.
