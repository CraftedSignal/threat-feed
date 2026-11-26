---
brief_id: brief-2026-11-23-redhat-jboss-vulnerabilities
event_id: brief-2026-11-23-redhat-jboss-vulnerabilities
revision: 2
activity_at: "2026-11-26T19:08:55Z"
revision_history:
  - revision: 2
    at: "2026-11-26T19:08:55Z"
    checksum: sha256:1a867440a49b6acc9515ea82d9ac8210d106b34ffce303257ab458a71d02e629
    summary: added CVE-2023-5379
    changed_fields:
      - cpes
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2023-5379
title: 'Red Hat JBoss Enterprise Application Platform: Multiple vulnerabilities'
slug: 2026-11-redhat-jboss-vulnerabilities
description: Multiple vulnerabilities in Red Hat JBoss Enterprise Application Platform enable remote attackers to bypass security controls, conduct denial-of-service, disclose information, manipulate data, or execute arbitrary code.
date: "2026-11-23T16:43:13Z"
lastmod: "2026-11-26T19:06:28Z"
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
cpes:
  - cpe:2.3:a:redhat:jboss_enterprise_application_platform:-:*:*:*:text-only:*:*:*
  - cpe:2.3:a:redhat:jboss_enterprise_application_platform:7.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:single_sign-on:7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:undertow:-:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - JBoss Enterprise Application Platform
cve_verification:
  CVE-2023-5379:
    status: verified
    source: nvd
    checked_at: 2026-11-26T19:06:28.676133399Z
cves:
  - id: CVE-2023-5379
    cvss: 7.5
    epss: 0.01157
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4715
  - https://nvd.nist.gov/vuln/detail/CVE-2023-5379
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Perform enterprise asset inventory to identify all active instances of JBoss Enterprise Application Platform.
      owner: IT Operations
      due: 48h
      evidence: BSI notification of multiple critical vulnerabilities in the software.
  enrichment_needed:
    - item: Specific CVE identifiers for the vulnerabilities mentioned in WID-SEC-2026-4715.
      owner: CTI
      reason: The source identifies the vulnerabilities generically; CVEs are required to map to specific exploit vectors and vendor patches.
      evidence: Source provides a high-level summary but lacks specific vulnerability tracking IDs.
  hunt_leads:
    - lead: Monitor web server and application logs for unusual request patterns, specifically those attempting directory traversal, command injection, or unauthorized configuration changes targeting JBoss administration endpoints.
      data_needed:
        - Web application access logs
        - JBoss server error logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory notes the potential for arbitrary code execution and information disclosure.
updates:
  - at: "2026-11-26T19:06:28Z"
    level: L2
    summary: added CVE-2023-5379
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2023-5379
---

## Overview

The BSI has identified multiple vulnerabilities in Red Hat JBoss Enterprise Application Platform. These flaws allow unauthenticated or remote attackers to perform a variety of malicious actions, including bypassing security restrictions, executing arbitrary code, disclosing sensitive information, performing denial-of-service attacks, and manipulating data. No specific CVEs were cited in the initial advisory.

## Recommendation

- Immediately audit current deployments of Red Hat JBoss Enterprise Application Platform to identify installed versions.
- Monitor Red Hat Security Advisories (RHSA) and the JBoss product portal for specific version-level remediation paths and official patches.
- Implement strict access controls and network segmentation for JBoss instances to limit exposure to untrusted networks while patches are prepared.
