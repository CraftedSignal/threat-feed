---
brief_id: brief-2026-11-17-openssl-vulnerabilities-b6059df5
event_id: brief-2026-11-17-openssl-vulnerabilities-b6059df5
revision: 1
activity_at: "2026-11-17T15:16:55Z"
title: 'OpenSSL: Multiple Denial of Service Vulnerabilities (CVE-2026-107493, CVE-2026-124709, CVE-2026-35190)'
slug: 2026-11-openssl-vulnerabilities-b6059df5
description: Multiple vulnerabilities in OpenSSL versions 1.0.2 through 4.1.1 allow remote attackers to cause application crashes, memory corruption, or resource exhaustion.
date: "2026-11-17T15:16:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
vendors:
  - OpenSSL
products:
  - OpenSSL 1.0.2
  - OpenSSL 1.1.1
  - OpenSSL 3.0.0
  - OpenSSL 3.5.0
  - OpenSSL 4.0.0
  - OpenSSL 4.1.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Remote attacker can cause a Denial of Service through memory corruption, exhaustion, or crashes.
    confidence_band: high
cves:
  - id: CVE-2026-107493
    kev_status: "false"
  - id: CVE-2026-124709
    kev_status: "false"
  - id: CVE-2026-35190
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1554/
  - https://openssl-library.org/news/secadv/20261117.txt
  - https://cveawg.mitre.org/api/cve/CVE-2026-107493
  - https://cveawg.mitre.org/api/cve/CVE-2026-124709
  - https://cveawg.mitre.org/api/cve/CVE-2026-35190
action_plan:
  hunt_leads:
    - lead: Identify endpoints running vulnerable versions of OpenSSL (3.5.x < 3.5.10, 4.0.x < 4.0.4, 4.1.x < 4.1.1) to prioritize patching and monitor for unusual service crashes or restarts that could indicate exploitation of CVE-2026-107493, CVE-2026-124709, or CVE-2026-35190.
      technique_id: T1499
      data_needed:
        - Software inventory logs
        - Application crash logs
        - System service management logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: De multiples vulnérabilités ont été découvertes dans OpenSSL. Elles permettent à un attaquant de provoquer un déni de service à distance.
---

## Overview
Multiple vulnerabilities have been identified in various versions of OpenSSL, potentially leading to denial-of-service conditions.

## Vulnerability Details
- **CVE-2026-107493 (Use After Free):** Applications that pass an existing, non-null stack to PEM_X509_INFO_read_bio_ex() are vulnerable if a read operation fails. The function may free entries in the stack while keeping pointers to them, which can lead to crashes or memory corruption when the stack is accessed. This affects OpenSSL 1.0.2 (<1.0.2zt), 1.1.1 (<1.1.1zk), 3.0.0 (<3.0.24), 3.5.0 (<3.5.10), 4.0.0 (<4.0.4), and 4.1.0 (<4.1.1).
- **CVE-2026-124709 (Missing Release of Memory):** QUIC servers may retain stream state if a peer resets a stream before a rejection is acknowledged. A client that repeatedly opens and resets streams can cause unbounded memory growth until the process crashes. This affects OpenSSL 3.5.0 (<3.5.10), 4.0.0 (<4.0.4), and 4.1.0 (<4.1.1).
- **CVE-2026-35190 (Out-of-Bounds Read):** Servers with Suite B certificate flags enabled and TLS 1.3 active can read past the end of a static group list during ClientHello processing. This may cause a process crash on systems with hardened allocators. This affects OpenSSL 3.5.0 (<3.5.10), 4.0.0 (<4.0.4), and 4.1.0 (<4.1.1).

## Impact
Successful exploitation can result in application crashes or denial-of-service. The provided sources do not specify remote code execution or memory disclosure capabilities.

## Recommendation
Refer to the official OpenSSL security bulletin for remediation instructions and patch availability for affected versions.
