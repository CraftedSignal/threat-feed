---
title: Containerd runAsNonRoot Bypass via Crafted User Directive (CVE-2026-46680)
slug: 2026-05-containerd-runasnonroot-bypass
description: A vulnerability in containerd allows for bypassing the Kubernetes `runAsNonRoot` restriction by exploiting a misinterpretation of large numeric User directives in container images, potentially leading to container execution as root (UID 0); this is tracked as CVE-2026-46680 and CVE-2024-40635.
date: "2026-05-21T21:41:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:linuxfoundation:containerd:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
tags:
  - runAsNonRoot
  - privilege-escalation
  - containerd
  - kubernetes
vendors:
  - containerd
products:
  - containerd/containerd
  - containerd/containerd/v2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-40635
    cvss: 4.6
    epss: 0.00062
references:
  - https://github.com/advisories/GHSA-fqw6-gf59-qr4w
  - https://containerd.io/releases/#current-state-of-containerd-releases
  - https://github.com/advisories/GHSA-265r-hfxg-fhmg
  - https://github.com/containerd/project/blob/main/SECURITY.md
rules:
  - title: Detect Containerd runAsNonRoot Bypass via Large UID
    description: Detects deployments where an image specifies a large UID, potentially exploiting CVE-2026-46680 to bypass runAsNonRoot.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious /etc/passwd Modification in Container Build
    description: Detects attempts to modify /etc/passwd during container image creation with potentially malicious intent (CVE-2026-46680 mitigation).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists within containerd that allows a malicious container image to bypass the `runAsNonRoot` security context in Kubernetes. This occurs when a container image specifies a numeric `User` directive that is too large to be parsed as a standard 32-bit integer, which containerd then incorrectly interprets as a username. If the attacker crafts a malicious image with an `/etc/passwd` file that maps this large numeric string to root, the container will execute as root, subverting intended security policies. This issue affects containerd versions before 2.3.1, 2.2.4, 2.0.9, and 1.7.32. Exploitation could lead to unauthorized access and privilege escalation within the containerized environment. This bypass impacts security implementations relying on `runAsNonRoot` to enforce least privilege. The vulnerability is identified as CVE-2026-46680 and CVE-2024-40635.

## Attack Chain

1.  Attacker creates a malicious container image with a crafted `/etc/passwd` file.
2.  The `/etc/passwd` file maps a large numeric string (e.g., "9999999999") to UID 0 (root).
3.  The Dockerfile for the image includes a `USER` directive using this large numeric string (e.g., `USER 9999999999`).
4.  The attacker deploys a pod to Kubernetes that uses the malicious image, but includes the `runAsNonRoot: true` securityContext option to enforce non-root execution.
5.  Containerd attempts to start the container. Due to the vulnerability, containerd misinterprets the large numeric string as a username.
6.  Containerd consults the `/etc/passwd` file within the image and incorrectly resolves the large numeric username to UID 0 (root).
7.  The container is launched and executes as root, bypassing the intended `runAsNonRoot` restriction.
8.  Attacker gains unauthorized root access within the container, potentially escalating privileges further within the cluster.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass the `runAsNonRoot` security context in Kubernetes, forcing containers to run as root even when explicitly restricted. This can lead to privilege escalation, unauthorized access to sensitive data, and potential compromise of the entire Kubernetes cluster. The impact is especially severe in environments where `runAsNonRoot` is a critical security control for preventing container escape and lateral movement. The number of affected systems depends on the prevalence of vulnerable containerd versions and the reliance on `runAsNonRoot` for security enforcement.

## Recommendation

*   Upgrade containerd to versions 2.3.1, 2.2.4, 2.0.9, or 1.7.32 to patch the vulnerability as described in the advisory [GHSA-fqw6-gf59-qr4w].
*   Enforce a specific numeric `runAsUser` in the Kubernetes Pod `securityContext` to override the `USER` directive in the image as a workaround.
*   Deploy the Sigma rule "Detect Containerd runAsNonRoot Bypass via Large UID" to identify exploitation attempts by detecting pods using images with a large UID as the user.
*   Monitor container images for suspicious `/etc/passwd` files that map large numeric strings to UID 0.
