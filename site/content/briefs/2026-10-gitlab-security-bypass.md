---
brief_id: brief-2026-10-30-gitlab-security-bypass
event_id: brief-2026-10-30-gitlab-security-bypass
revision: 1
activity_at: "2026-10-30T21:20:03Z"
title: 'GitLab: Security policy bypass vulnerability'
slug: 2026-10-gitlab-security-bypass
description: A vulnerability has been discovered in GitLab products that allows an attacker to cause a security policy bypass.
date: "2026-10-30T21:20:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
vendors:
  - GitLab
products:
  - AI Gateway
  - GitLab Community Edition
  - GitLab Enterprise Edition
cves:
  - id: CVE-2026-111943
    cvss: 6.8
    epss: 0.00299
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1427/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-3-released/
  - https://www.cve.org/CVERecord?id=CVE-2026-111943
---

A security policy bypass vulnerability has been identified in GitLab products. This flaw allows an attacker to bypass security policy controls. Users are advised to refer to the vendor's security bulletin for patch information.
