---
title: Red Hat OpenShift AI odh-dashboard Kubernetes Token Disclosure (CVE-2026-5483)
slug: 2026-04-openshift-token-disclosure
description: CVE-2026-5483 is a high-severity vulnerability in the `odh-dashboard` component of Red Hat OpenShift AI (RHOAI) that allows for the disclosure of Kubernetes Service Account tokens through a NodeJS endpoint, potentially leading to unauthorized access to Kubernetes resources.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
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

A vulnerability, CVE-2026-5483, has been identified in the `odh-dashboard` component of Red Hat OpenShift AI (RHOAI). This flaw allows for the unintended disclosure of Kubernetes Service Account tokens via a NodeJS endpoint. Discovered in April 2026, the vulnerability stems from the insertion of sensitive information into sent data. An attacker with knowledge of the vulnerable endpoint can potentially exploit this to gain unauthorized access to Kubernetes resources within the affected OpenShift environment. This poses a significant risk, particularly in environments where OpenShift AI is used to manage sensitive data or critical infrastructure.

## Attack Chain

1.  The attacker identifies a Red Hat OpenShift AI instance running the vulnerable `odh-dashboard` component.
2.  The attacker crafts a malicious HTTP request targeting the vulnerable NodeJS endpoint responsible for handling Kubernetes Service Account tokens.
3.  The vulnerable endpoint processes the request without proper sanitization or access controls.
4.  The Kubernetes Service Account token is inadvertently included in the response data due to the CWE-201 vulnerability (Insertion of Sensitive Information Into Sent Data).
5.  The attacker intercepts or captures the response containing the leaked Kubernetes Service Account token.
6.  The attacker uses the compromised Kubernetes Service Account token to authenticate to the Kubernetes API.
7.  The attacker enumerates the Kubernetes cluster to identify potential targets and resources.
8.  The attacker leverages the compromised Service Account privileges to access sensitive data, modify configurations, or deploy malicious workloads within the Kubernetes cluster.

## Impact

Successful exploitation of CVE-2026-5483 can lead to unauthorized access to Kubernetes resources within a Red Hat OpenShift AI environment. The disclosure of Kubernetes Service Account tokens allows an attacker to bypass authentication controls and potentially gain complete control over the cluster. This could result in data breaches, service disruptions, and the deployment of malicious applications, affecting all users and applications relying on the compromised OpenShift AI instance. The severity is high, with a CVSS v3.1 base score of 8.5.

## Recommendation

*   Apply the patch provided by Red Hat via RHSA-2026:7397 to remediate the vulnerability in `odh-dashboard`.
*   Monitor web server logs for suspicious requests targeting NodeJS endpoints associated with `odh-dashboard` using the "Detect OpenShift Token Disclosure Attempt" Sigma rule.
*   Implement network segmentation to limit the impact of a potential compromise and restrict access to sensitive Kubernetes resources.
*   Enable and review Kubernetes audit logs to detect unauthorized activity performed by compromised service accounts.
*   Rotate Kubernetes Service Account tokens regularly to minimize the window of opportunity for an attacker to exploit leaked credentials.
