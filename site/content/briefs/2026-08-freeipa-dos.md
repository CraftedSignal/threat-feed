---
title: Denial of Service Vulnerability in FreeIPA Migration Handler
slug: 2026-08-freeipa-dos
description: An unauthenticated remote denial-of-service vulnerability in FreeIPA, tracked as CVE-2026-73197, allows attackers to exhaust system memory by sending oversized form POST requests to the migration endpoint.
date: "2026-08-20T13:14:57Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - cve-2026-73197
vendors:
  - Red Hat
products:
  - FreeIPA
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
affected_os:
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This can force the migration handler to read attacker-controlled request bodies fully into memory, leading to increased memory usage, slower request handling, and potential service disruption or denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-73197
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73197
  - https://access.redhat.com/security/cve/CVE-2026-73197
  - https://bugzilla.redhat.com/show_bug.cgi?id=2474697
rules:
  - title: Detect CVE-2026-73197 Exploitation - Large POST Request to FreeIPA Migration Endpoint
    description: Detects potential exploitation attempts by monitoring for POST requests to the migration endpoint with unusually large content-length headers.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch FreeIPA on all RHEL systems
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-73197 vendor fix availability
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/proxy to limit POST body size for /ipa/migration/migration.py
      owner: IT Operations
      addresses: CVE-2026-73197
      evidence: NVD vulnerability description recommends limiting resources
---

CVE-2026-73197 is a high-severity vulnerability discovered in FreeIPA, specifically impacting the `/ipa/migration/migration.py` endpoint. An unauthenticated remote attacker can exploit this flaw by sending specially crafted, oversized form POST requests to the migration handler. 

The vulnerability stems from improper resource management (CWE-770: Allocation of Resources Without Limits or Throttling), where the application attempts to read the entire attacker-controlled request body into memory without applying limits. Successive or large concurrent requests of this nature result in significant memory consumption, degrading request processing performance, and eventually leading to a complete service disruption or denial-of-service (DoS) state. This affects various Red Hat Enterprise Linux versions where the FreeIPA package is deployed. Defenders should prioritize limiting request body sizes or applying rate-limiting/WAF rules to the affected migration endpoint.

## Impact

Successful exploitation results in a denial-of-service condition, rendering the FreeIPA service unavailable to legitimate users. This impacts authentication and identity management services across organizations relying on FreeIPA for directory and PKI services.

## Recommendation

* Apply vendor-supplied patches for the FreeIPA package as released by Red Hat.
* Implement request body size limits on web application firewalls (WAF) or reverse proxies (such as Apache or Nginx) protecting the `/ipa/migration/migration.py` URI.
* Monitor web server access logs for anomalous, high-frequency, or large-payload POST requests directed at the migration endpoint.
