---
title: Red Hat OpenShift AI Llama Stack Unauthorized Access Vulnerability (CVE-2025-12805)
slug: 2026-03-openshift-ai-vuln
description: CVE-2025-12805 describes a flaw in Red Hat OpenShift AI (RHOAI) llama-stack-operator that allows unauthorized access to Llama Stack services in other namespaces via direct network requests due to missing NetworkPolicy restrictions, potentially enabling attackers to view or manipulate sensitive data.
date: "2026-03-27T10:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - openshift
  - kubernetes
  - networkpolicy
  - unauthorized-access
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12805
  - https://access.redhat.com/errata/RHSA-2026:2106
  - https://access.redhat.com/errata/RHSA-2026:2695
  - https://access.redhat.com/security/cve/CVE-2025-12805
  - https://bugzilla.redhat.com/show_bug.cgi?id=2413101
rules:
  - title: Detect Direct Network Connection to Llama Stack Service from Different Namespace
    description: Detects network connections to the llama-stack service endpoint originating from a different OpenShift namespace, indicating potential unauthorized access attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthorized Access to Llama Stack Service Endpoint
    description: Detects unauthorized access attempts to the Llama Stack service endpoint based on HTTP status codes indicating access denied or forbidden.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability, CVE-2025-12805, has been identified in Red Hat OpenShift AI (RHOAI) llama-stack-operator. The vulnerability stems from the lack of NetworkPolicy restrictions on the llama-stack service endpoint. This allows a user within one namespace to bypass intended isolation and directly access Llama Stack services deployed in other namespaces. The vulnerability was published on March 26, 2026. Successful exploitation could lead to unauthorized data access and manipulation, impacting the…
