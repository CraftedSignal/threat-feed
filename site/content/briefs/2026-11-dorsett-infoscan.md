---
brief_id: brief-2026-11-17-dorsett-infoscan
event_id: brief-2026-11-17-dorsett-infoscan
revision: 1
activity_at: "2026-11-17T17:26:18Z"
title: 'Dorsett Controls InfoScan: Multiple Vulnerabilities (CVE-2026-117659, CVE-2026-120157, CVE-2026-120255, CVE-2026-120260, CVE-2026-120271, CVE-2026-120298)'
slug: 2026-11-dorsett-infoscan
description: Dorsett Controls InfoScan is affected by six vulnerabilities, including insecure Electron configurations, credential exposure through hard-coded keys, and multiple unauthenticated information disclosure endpoints that facilitate system reconnaissance and credential recovery.
date: "2026-11-17T17:26:18Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Content verified against CISA ICSA-26-321-01
tags:
  - cve
  - vulnerability
  - ics
  - information-disclosure
vendors:
  - Dorsett Controls
products:
  - InfoScan
product_versions:
  - product: InfoScan
    range: < 1.46
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A remote attacker can send HTTP requests without authentication to retrieve system configuration information, including usernames and display names, multifactor authentication configuration status, session settings, application version information, server details, hardware module firmware versions, and the BACnet/IP port used by the installation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Because the cryptographic material is embedded in the distributed application, an individual with access to the encrypted registry value and the application code may be able to recover the database password.
    confidence_band: high
cves:
  - id: CVE-2026-117659
    kev_status: "false"
  - id: CVE-2026-120157
    kev_status: "false"
  - id: CVE-2026-120255
    kev_status: "false"
  - id: CVE-2026-120260
    kev_status: "false"
  - id: CVE-2026-120271
    kev_status: "false"
  - id: CVE-2026-120298
    kev_status: "false"
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-321-01
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all InfoScan instances to version 1.46 or later.
      owner: IT Operations
      due: 72h
      evidence: Dorsett Controls recommends updating affected versions of InfoScan to v1.46 or higher.
  hunt_leads:
    - lead: Monitor web server or proxy logs for repeated unauthenticated access to /mobile-enumeration or /version-reporting endpoints which may indicate reconnaissance activity.
      technique_id: T1592
      data_needed:
        - web server request logs
        - HTTP proxy logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: A remote attacker can send HTTP requests without authentication to retrieve system configuration information.
  mitigation_plan:
    - priority: immediate
      action: Isolate all InfoScan systems from the public internet and restrict access to internal networks.
      owner: IT Operations
      addresses: General network hardening
      evidence: Minimize network exposure for all control system devices and/or systems, ensuring they are not accessible from the internet.
---

## Overview
Dorsett Controls InfoScan contains several critical vulnerabilities that may lead to the exposure of sensitive system information, unauthorized data access, credential recovery, and interception of network communications. These issues affect various components of the InfoScan application, including the Electron desktop client, the installer, and backend API endpoints. No known public exploitation has been reported as of the advisory date.

## Vulnerability Details
- **CVE-2026-117659**: The InfoScan Electron desktop client improperly validates TLS certificates and runs with insecure Electron security settings (nodeIntegration enabled, contextIsolation disabled, webSecurity disabled), weakening boundary protections.
- **CVE-2026-120157**: The installer exposes internal hostnames for customer installations, development, and testing infrastructure.
- **CVE-2026-120255**: Database-encryption implementations use hard-coded cryptographic keys and initialization vectors, potentially allowing for the recovery of MongoDB passwords stored in the Windows registry.
- **CVE-2026-120260**: Unauthenticated access to an endpoint used for retrieving sales-automation templates.
- **CVE-2026-120271**: Unauthenticated information disclosure in mobile-enumeration and version-reporting endpoints, leaking system configurations, usernames, MFA status, and network port details.
- **CVE-2026-120298**: Insufficient error handling in login and password-reset endpoints leaks detailed Node.js stack traces, including internal paths and source file metadata.

## Recommendation
Upgrade InfoScan to version 1.46 or higher immediately. Administrators can initiate updates via the System Maintenance menu within the application or by downloading the update from the Dorsett Controls Customer Portal. Additionally, isolate control system networks from the internet and business networks using firewalls and VPNs where remote access is necessary.
