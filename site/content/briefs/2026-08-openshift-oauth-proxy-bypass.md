---
title: Security Bypass Vulnerability in Red Hat OpenShift oauth-proxy
slug: 2026-08-openshift-oauth-proxy-bypass
description: A vulnerability in the Red Hat OpenShift oauth-proxy component, identified as CVE-2024-5254, allows a remote authenticated attacker to bypass security controls and manipulate data.
date: "2026-08-11T11:59:21Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:brainstormforce:ultimate_addons_for_wpbakery_page_builder:*:*:*:*:*:wordpress:*:*
vendors:
  - Red Hat
products:
  - OpenShift Container Platform
cves:
  - id: CVE-2024-5254
    cvss: 6.4
    epss: 0.00297
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2749
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch OpenShift Container Platform to the version containing the fix for CVE-2024-5254.
      owner: IT Operations
      due: 72h
      evidence: Vendor advisory requires software update for mitigation.
  mitigation_plan:
    - priority: immediate
      action: Update OpenShift Container Platform to patched release.
      owner: IT Operations
      addresses: CVE-2024-5254
      evidence: BSI security advisory.
---

Red Hat has identified a security vulnerability affecting the oauth-proxy component within the OpenShift Container Platform, tracked as CVE-2024-5254. This flaw allows a remote, authenticated attacker to bypass established security restrictions. The vulnerability stems from improper handling of specific request patterns during the authentication and authorization flow. An attacker successful in exploiting this vulnerability can manipulate data or perform unauthorized operations within the affected OpenShift environment. Because the proxy is a critical component for managing access to containerized services, this flaw poses a risk to the integrity of service deployments and the underlying data accessed through the OpenShift API. Defenders should prioritize patching affected OpenShift clusters to mitigate the risk of unauthorized access and potential data manipulation by authenticated entities within the environment.

## Impact

Successful exploitation of this vulnerability permits an authenticated attacker to perform actions that should be restricted by the oauth-proxy, leading to potential unauthorized data modification or administrative actions within the cluster. This affects organizations relying on OpenShift for secure container orchestration and service access control.

## Recommendation

- Apply the security update provided by Red Hat for the OpenShift Container Platform to remediate CVE-2024-5254 across all cluster environments.
- Review OpenShift audit logs for unexpected or anomalous HTTP requests targeting the oauth-proxy endpoint, particularly those utilizing atypical URL path patterns.
- Verify authorization policies are correctly enforced for sensitive services behind the proxy following the application of the vendor-supplied patch.
