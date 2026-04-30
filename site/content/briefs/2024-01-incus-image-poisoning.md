---
title: Incus Image Cache Poisoning Vulnerability
slug: 2024-01-incus-image-poisoning
description: A vulnerability exists in Incus where it does not properly verify the combined fingerprint when downloading images from simplestreams servers, allowing an attacker to perform image cache poisoning and potentially expose other tenants to running attacker-controlled images.
date: "2026-03-27T17:08:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - incus
  - image-poisoning
  - simplestreams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-p8mm-23gg-jc9r
iocs:
  - type: url
    value: https://images.linuxcontainers.org/streams/v1/{index,images}.json
  - type: url
    value: https://images.linuxcontainers.org/images/DISTRO/RELEASE/ARCH/default/NEWEST/{incus.tar.xz,rootfs.squashfs}
  - type: domain
    value: images.linuxcontainers.org
ioc_counts:
  domain: 1
  url: 2
rules:
  - title: Detect Suspicious Incus Image Download
    description: Detects network connections from Incus to non-standard image servers, indicating a potential image poisoning attempt.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - network_connection
      - linux
  - title: Detect Modified SquashFS Files
    description: Detects the presence of squashfs files with unexpected modifications in Incus instances, potentially indicating image tampering.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability in Incus allows for image cache poisoning when downloading images from simplestreams servers. The vulnerability stems from the lack of validation of the combined fingerprint of image files, potentially leading to a compromised image being served to other users. This issue affects Incus servers that have not configured `restricted.image.servers` or equivalent firewall rules, making them susceptible to this attack. An attacker with access to such an Incus environment can manipulate the image server to serve altered image files under the same fingerprint, poisoning the global image cache. This attack can be particularly effective on systems that frequently deploy new Incus instances, such as CI or build servers, allowing an attacker to inject malicious code into unsuspecting users' instances.

## Attack Chain

1.  The attacker gains access to an Incus server that lacks `restricted.image.servers` configuration or equivalent network restrictions.
2.  The attacker monitors the legitimate image server (`images.linuxcontainers.org`) for newly published images.
3.  The attacker creates a compromised image with the same fingerprint as the legitimate image on an attacker-controlled server (`TESTSERVER`). This involves modifying the `rootfs.squashfs` file.
4.  The attacker updates the `images.json` file on their server to reflect the changes made to the `rootfs.squashfs` file, including the new SHA256 hash and size.
5.  The attacker configures their server to serve the modified image files and the updated `images.json` file over HTTPS.
6.  The attacker waits for a target user on the vulnerable Incus server to request the legitimate image using `incus image copy`.
7.  The vulnerable Incus server downloads the compromised image from the attacker-controlled server (`TESTSERVER`) due to the lack of combined fingerprint validation.
8.  The next time the target user launches a new instance using the compromised image (e.g., `incus launch images:debian/trixie`), the attacker's injected code is executed.

## Impact

Successful exploitation leads to image cache poisoning, potentially affecting multiple users on the same Incus server. The attacker can inject malicious code into the compromised image, leading to arbitrary code execution within the user's Incus instances. The impact is most significant in multi-tenant environments where multiple users share the same Incus server, as a single compromised image can affect multiple users and their workloads.

## Recommendation

*   Implement `restricted.image.servers` in project configuration to restrict image sources to trusted servers. This mitigates the risk of downloading images from attacker-controlled servers (reference: Overview).
*   Implement network restrictions through firewalling or an HTTP proxy server to prevent Incus servers from accessing untrusted image servers (reference: Overview).
*   Monitor network connections originating from Incus servers to detect connections to unauthorized or suspicious image servers using the `Detect Suspicious Incus Image Download` Sigma rule.
*   Deploy the `Detect Modified SquashFS Files` Sigma rule to identify instances using potentially tampered image files.
