---
title: Red Hat Open Cluster Management (OCM) Cross-Cluster Privilege Escalation via Forged Certificates (CVE-2026-4740)
slug: 2026-04-ocm-privesc
description: CVE-2026-4740 describes a vulnerability in Red Hat Open Cluster Management (OCM) where improper validation of Kubernetes client certificate renewal allows a managed cluster administrator to forge certificates, enabling cross-cluster privilege escalation.
date: "2026-04-07T15:17:46Z"
severities:
  - critical
type: advisory
types:
  - advisory
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

A critical vulnerability, CVE-2026-4740, exists within Red Hat Advanced Cluster Management (ACM), which utilizes Open Cluster Management (OCM) technology. This flaw stems from the improper validation of Kubernetes client certificate renewal requests. A malicious managed cluster administrator can exploit this vulnerability to forge a client certificate. This forged certificate, if approved by the OCM controller, grants the attacker elevated privileges across different clusters. The successful exploitation of this vulnerability can lead to an attacker gaining complete control over other managed clusters and potentially the central hub cluster, posing a significant threat to the entire ACM environment. This vulnerability impacts any environment utilizing Red Hat Advanced Cluster Management.

## Attack Chain

1.  A managed cluster administrator gains initial access to a managed Kubernetes cluster within the ACM environment.
2.  The attacker crafts a malicious Kubernetes client certificate renewal request, exploiting the lack of proper validation in OCM.
3.  The forged certificate request is submitted to the OCM controller for approval.
4.  Due to insufficient validation, the OCM controller approves the forged client certificate.
5.  The attacker uses the approved, forged certificate to authenticate to other managed clusters.
6.  Using the forged certificate, the attacker escalates privileges within the targeted managed clusters.
7.  The attacker leverages escalated privileges to move laterally across the cluster.
8.  The attacker gains control of the targeted managed clusters, potentially including the central hub cluster, allowing for data exfiltration, service disruption, or other malicious activities.

## Impact

Successful exploitation of CVE-2026-4740 can lead to complete compromise of the Red Hat Advanced Cluster Management environment. A malicious managed cluster administrator can leverage this vulnerability to gain control over other managed clusters, including the hub cluster. This allows for unauthorized access to sensitive data, disruption of critical services, and potential deployment of malicious workloads across the compromised clusters. The vulnerability has a CVSS v3.1 score of 8.2, indicating a high severity. The number of potential victims depends on the scope of ACM deployments.

## Recommendation

*   Apply the patch or upgrade to a version of Red Hat Advanced Cluster Management (ACM) that addresses CVE-2026-4740 to remediate the improper certificate validation.
*   Implement stricter validation policies for Kubernetes client certificate renewal requests within your OCM environment to prevent the forging of certificates.
*   Monitor Kubernetes API server logs for suspicious certificate creation or approval activities, using the `title: "Detect Suspicious Kubernetes Certificate Creation"` Sigma rule provided below.
*   Implement Role-Based Access Control (RBAC) policies within your Kubernetes clusters to limit the privileges of managed cluster administrators and mitigate the impact of potential privilege escalation.
*   Monitor the OCM controller logs for certificate-related events as they relate to CVE-2026-4740.
