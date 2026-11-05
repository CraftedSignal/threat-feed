---
brief_id: brief-2026-11-05-vitafit-tls-vuln
event_id: brief-2026-11-05-vitafit-tls-vuln
revision: 1
activity_at: "2026-11-05T00:07:15Z"
title: 'VitaFit Android Application: Insecure SSL/TLS certificate validation (CVE-2026-54372)'
slug: 2026-11-vitafit-tls-vuln
description: The VitaFit Android application (com.vt.vitafit) before version 2.8.1.0 contains an insecure TLS/SSL certificate validation vulnerability allowing man-in-the-middle attacks.
date: "2026-11-05T00:07:15Z"
lastmod: "2026-11-05T00:07:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:vitafit:vitafit:*:*:*:*:*:android:*:*
vendors:
  - VitaFit
products:
  - VitaFit Android application (com.vt.vitafit) before 2.8.1.0
  - VitaFit Android application (< 2.8.1.0)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592.002
    technique_name: Software
    evidence: A malicious application can register the same custom URI scheme used by the legitimate application to intercept Fitbit OAuth authorization tokens.
    confidence_band: high
cves:
  - id: CVE-2026-54372
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-54376
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54372
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54376
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Verify version of VitaFit application across mobile device management (MDM) inventory
      owner: IT Operations
      due: 48h
      evidence: VitaFit Android application before 2.8.1.0 is affected.
  hunt_leads:
    - lead: Identify applications installed on enterprise-managed devices that register the vitafit:// custom URI scheme
      technique_id: T1592.002
      data_needed:
        - MDM/UEM inventory of installed packages and registered URI handlers
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers register the same callback scheme (vitafit://vtio.cn) to intercept tokens.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to VitaFit version 2.8.1.0 or later
      owner: IT Operations
      addresses: CVE-2026-54376
      evidence: NVD advisory states fixed in 2.8.1.0.
updates:
  - at: "2026-11-05T00:07:36Z"
    level: L2
    summary: added coverage for VitaFit Android application (< 2.8.1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54376
---

The VitaFit Android application (com.vt.vitafit) before version 2.8.1.0 contains an insecure TLS/SSL certificate validation vulnerability. The application uses a custom X509TrustManager that trusts all certificates and a hostname verifier that accepts any hostname. 

Network-based attackers can perform a man-in-the-middle attack to intercept and modify HTTPS traffic. This allows attackers to capture account sessions and health-related API data, and use a captured session to delete the account's authentication record and prevent legitimate login.
