---
title: ArgoCD Image Updater Namespace Bypass Vulnerability (CVE-2026-6388)
slug: 2026-04-argocd-privesc
description: CVE-2026-6388 describes a flaw in ArgoCD Image Updater that allows an attacker with permissions to create or modify an ImageUpdater resource in a multi-tenant environment to bypass namespace boundaries and trigger unauthorized image updates.
date: "2026-04-15T22:17:22Z"
severities:
  - critical
tags:
  - argocd
  - privilege-escalation
  - kubernetes
  - cve-2026-6388
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6388
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6388
  - https://access.redhat.com/security/cve/CVE-2026-6388
  - https://bugzilla.redhat.com/show_bug.cgi?id=2458766
rules:
  - title: Detect Suspicious ArgoCD ImageUpdater Resource Modification
    description: Detects modifications to ImageUpdater resources that may attempt to target applications in different namespaces, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect ArgoCD ImageUpdater Unauthorized Image Update
    description: Detects an attempt to update a container image in a namespace other than the one associated with the user's permissions.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-6388 is a critical vulnerability affecting ArgoCD Image Updater. This flaw allows an attacker who has the ability to create or modify ImageUpdater resources within a multi-tenant ArgoCD environment to bypass namespace boundaries. By exploiting insufficient validation within the Image Updater, an attacker can trigger image updates for applications residing in different namespaces, effectively escalating privileges across tenant boundaries. This unauthorized modification of application…
