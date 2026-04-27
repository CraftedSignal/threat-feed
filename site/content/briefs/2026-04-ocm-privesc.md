---
title: Red Hat Open Cluster Management (OCM) Cross-Cluster Privilege Escalation via Forged Certificates (CVE-2026-4740)
slug: 2026-04-ocm-privesc
description: CVE-2026-4740 describes a vulnerability in Red Hat Open Cluster Management (OCM) where improper validation of Kubernetes client certificate renewal allows a managed cluster administrator to forge certificates, enabling cross-cluster privilege escalation.
date: "2026-04-07T15:17:46Z"
severities:
  - critical
tags:
  - kubernetes
  - privilege-escalation
  - cve-2026-4740
  - ocm
  - acm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4740
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4740
  - https://access.redhat.com/security/cve/CVE-2026-4740
  - https://blog.arfevrier.fr/open-cluster-management-cross-cluster-escape/
  - https://bugzilla.redhat.com/show_bug.cgi?id=2450590
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Kubernetes Certificate Creation
    description: Detects the creation of Kubernetes certificates, which could be related to CVE-2026-4740 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Kubernetes Certificate Approval
    description: Detects suspicious approval of Kubernetes certificates, which could be related to CVE-2026-4740 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-4740, exists within Red Hat Advanced Cluster Management (ACM), which utilizes Open Cluster Management (OCM) technology. This flaw stems from the improper validation of Kubernetes client certificate renewal requests. A malicious managed cluster administrator can exploit this vulnerability to forge a client certificate. This forged certificate, if approved by the OCM controller, grants the attacker elevated privileges across different clusters. The successful…
