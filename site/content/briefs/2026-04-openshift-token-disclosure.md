---
title: Red Hat OpenShift AI odh-dashboard Kubernetes Token Disclosure (CVE-2026-5483)
slug: 2026-04-openshift-token-disclosure
description: CVE-2026-5483 is a high-severity vulnerability in the `odh-dashboard` component of Red Hat OpenShift AI (RHOAI) that allows for the disclosure of Kubernetes Service Account tokens through a NodeJS endpoint, potentially leading to unauthorized access to Kubernetes resources.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - openshift
  - kubernetes
  - token-disclosure
  - cve-2026-5483
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-5483
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5483
  - https://access.redhat.com/errata/RHSA-2026:7397
  - https://access.redhat.com/security/cve/CVE-2026-5483
  - https://bugzilla.redhat.com/show_bug.cgi?id=2454764
rules:
  - title: Detect OpenShift Token Disclosure Attempt
    description: Detects potential attempts to exploit CVE-2026-5483 by monitoring requests to the odh-dashboard NodeJS endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - webserver
      - linux
  - title: Detect Kubernetes API Access with Leaked Service Account Token
    description: Detects attempts to authenticate to the Kubernetes API using a potentially leaked Service Account Token
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A vulnerability, CVE-2026-5483, has been identified in the `odh-dashboard` component of Red Hat OpenShift AI (RHOAI). This flaw allows for the unintended disclosure of Kubernetes Service Account tokens via a NodeJS endpoint. Discovered in April 2026, the vulnerability stems from the insertion of sensitive information into sent data. An attacker with knowledge of the vulnerable endpoint can potentially exploit this to gain unauthorized access to Kubernetes resources within the affected OpenShift…
