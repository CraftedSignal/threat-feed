---
title: NetworkManager Local Privilege Escalation and Credential Theft via CA Path Manipulation
slug: 2026-08-networkmanager-ca-path-bypass
description: An improper authorization vulnerability in NetworkManager allows unprivileged local users to bypass 802.1X server certificate validation, facilitating credential theft through rogue access points.
date: "2026-08-24T22:03:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - local-privilege-escalation
  - linux
  - networking
  - 802.1x
  - vulnerability
vendors:
  - Red Hat
products:
  - NetworkManager
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 6
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Hardened Images
  - Red Hat OpenShift Container Platform 4
affected_os:
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 6
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This incomplete fix for CVE-2025-9615 allows an unprivileged local user to point a private WPA-Enterprise (802.1X) connection profile's CA path at an attacker-controlled directory, bypassing server certificate validation and enabling credential theft via a rogue access point.
    confidence_band: high
cves:
  - id: CVE-2026-19685
    cvss: 7.1
  - id: CVE-2025-9615
    cvss: 3.3
    epss: 0.00162
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19685
  - https://access.redhat.com/security/cve/CVE-2026-19685
  - https://bugzilla.redhat.com/show_bug.cgi?id=2515042
  - https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/commit/a8e87381a3e70060abd721d9a347f42b2ba68e6e
  - https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/merge_requests/2513
---

NetworkManager contains an authorization vulnerability, tracked as CVE-2026-19685, stemming from an incomplete fix for CVE-2025-9615. The issue involves the failure to apply 'private_user' restrictions to the '802-1x.ca-path' and 'phase2-ca-path' connection properties. This vulnerability permits an unprivileged local user on systems running affected versions of NetworkManager to modify the CA path within a WPA-Enterprise (802.1X) connection profile. By pointing these paths to an attacker-controlled directory, a local user can successfully bypass server certificate validation. This defect is particularly critical in enterprise environments where 802.1X is the primary mechanism for network authentication, as it enables the capture of user credentials via rogue access point (AP) interception. The issue specifically impacts Red Hat Enterprise Linux 10 and related infrastructure, as identified by Red Hat.

## Attack Chain

1. Attacker gains unprivileged access to a Linux system running an affected version of NetworkManager.
2. Attacker inspects existing WPA-Enterprise (802.1X) connection profiles.
3. Attacker uses NetworkManager command-line utilities (e.g., nmcli) to modify the '802-1x.ca-path' or 'phase2-ca-path' properties of a specific connection profile.
4. Attacker directs the modified CA path to a directory under their control containing a malicious, forged CA certificate.
5. Attacker deploys a rogue wireless access point configured to present the credentials required for the target network.
6. Victim system connects to the rogue AP, relying on the attacker-controlled CA path for validation.
7. NetworkManager successfully validates the connection against the attacker's forged certificate due to the bypass.
8. Attacker captures authentication credentials (e.g., EAP-MSCHAPv2 hashes) relayed by the victim during the 802.1X handshake.

## Impact

Successful exploitation allows for the interception of sensitive network credentials in enterprise environments. By bypassing certificate validation, an attacker can perform man-in-the-middle attacks on WPA-Enterprise wireless networks. This leads to unauthorized network access and potential lateral movement within the victim's organization. The severity is elevated to 'critical' by some assessments due to the potential for total impact on confidentiality and integrity of network authentication.

## Recommendation

* Prioritize updating NetworkManager packages across all systems running Red Hat Enterprise Linux 10 to the version containing the fix for CVE-2026-19685.
* Restrict local access to system configuration files and NetworkManager connection profiles using standard Linux file permissions to prevent unauthorized modification by unprivileged users.
* Monitor system logs for unexpected modifications to network connection profiles via 'nmcli' or direct file editing of '/etc/NetworkManager/system-connections/'.
* Review 802.1X deployment configurations to ensure consistent enforcement of server-side certificate verification in high-security zones.
