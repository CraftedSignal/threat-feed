---
title: CRI-O Environment Variable Injection Vulnerability (CVE-2026-15809)
slug: 2026-07-crio-env-var-injection
description: A critical vulnerability, CVE-2026-15809, in CRI-O allows an attacker with the ability to set container environment variables to bypass a previous fix (CVE-2022-4318), inject a newline character into the HOME environment variable, and add arbitrary lines to /etc/passwd, potentially leading to privilege escalation or persistence within the container.
date: "2026-07-15T13:19:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubernetes:cri-o:-:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_arm64:4.12:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_linuxone:4.12:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_power:4.12:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_ibm_z_systems:4.12:*:*:*:*:*:*:*
  - cpe:2.3:a:fedoraproject:extra_packages_for_enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:37:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_arm64:4.11:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_linuxone:4.11:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_for_power:4.11:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:openshift_container_platform_ibm_z_systems:4.11:*:*:*:*:*:*:*
tags:
  - container
  - linux
  - vulnerability
  - privilege-escalation
  - persistence
  - cri-o
vendors:
  - Red Hat, Inc.
products:
  - CRI-O
  - Red Hat OpenShift Container Platform 4
  - Red Hat Confidential Compute Attestation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This issue allows the addition of arbitrary lines into /etc/passwd by use of a specially crafted environment variable.
    confidence_band: high
cves:
  - id: CVE-2026-15809
    cvss: 7.8
  - id: CVE-2022-4318
    cvss: 7.8
    epss: 0.00266
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15809
  - https://access.redhat.com/security/cve/CVE-2026-15809
  - https://access.redhat.com/security/cve/cve-2022-4318
  - https://bugzilla.redhat.com/show_bug.cgi?id=2500846
  - https://github.com/cri-o/cri-o/pull/6450
  - https://github.com/cri-o/cri-o/pull/6524
rules:
  - title: Detect Linux /etc/passwd File Modification
    description: Detects suspicious modification to the /etc/passwd file, which can indicate exploitation of CVE-2026-15809 or other privilege escalation techniques that manipulate user accounts.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-15809, has been discovered in CRI-O, a container runtime interface for Kubernetes. This flaw represents an incomplete fix for a prior vulnerability, CVE-2022-4318. The issue allows an attacker who can set environment variables within a container to inject a newline character into the `HOME` environment variable. This maliciously crafted input is then processed by CRI-O in such a way that arbitrary lines can be added to the `/etc/passwd` file. Successful exploitation could lead to the creation of new user accounts or modification of existing ones, granting an attacker unintended privileges or establishing persistence within the affected container environment. This poses a significant risk to Kubernetes clusters utilizing vulnerable versions of CRI-O.

## Attack Chain

1. An attacker gains initial access to execute code within a container, with privileges sufficient to set environment variables for subsequent processes. This could be through another vulnerability, misconfiguration, or compromised legitimate credentials.
2. The attacker crafts a malicious `HOME` environment variable string. This string includes a newline character and specially formatted data intended to add or modify entries in the `/etc/passwd` file.
3. The vulnerable CRI-O container runtime processes the crafted `HOME` environment variable when a new process or container is launched with the attacker-controlled environment.
4. Due to the incomplete fix for CVE-2022-4318, CRI-O fails to properly sanitize the `HOME` environment variable, allowing the injected newline character to be interpreted.
5. This misinterpretation results in the arbitrary injection of the attacker-controlled lines into the `/etc/passwd` file, located either within the container or potentially on the host if privileges allow.
6. The injected lines create new user accounts, modify existing user's UIDs/GIDs, or establish other forms of account manipulation, effectively granting the attacker elevated privileges.
7. The attacker leverages the modified `/etc/passwd` file to gain privilege escalation (e.g., obtaining root access) or establish persistence within the compromised container or host system.

## Impact

Successful exploitation of CVE-2026-15809 allows an attacker to achieve privilege escalation and persistence within a compromised container environment. By injecting arbitrary lines into the `/etc/passwd` file, an attacker can create new privileged accounts or alter existing ones, effectively gaining control over the container. In some configurations, this could potentially lead to a container escape, granting access to the underlying host system. While specific victim numbers are not provided, any organization running affected versions of CRI-O in containerized environments, especially Kubernetes, is at risk of unauthorized access and system compromise.

## Recommendation

* Patch CVE-2026-15809 immediately by updating CRI-O to a patched version as recommended by Red Hat.
* Enable detailed file system auditing on Linux systems to detect suspicious modifications to critical system files like `/etc/passwd` as detected by the `Detect Linux /etc/passwd File Modification` Sigma rule.
* Monitor container environments for unusual process execution or attempts to modify sensitive system files within containers.
* Implement integrity monitoring for `/etc/passwd` and other critical system configuration files.
