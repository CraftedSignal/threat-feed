---
title: Out-of-Bounds Read in TIER IV Nebula
slug: 2026-08-nebula-oob-read
description: TIER IV Nebula through 1.2.0 is vulnerable to an out-of-bounds read in the Vlp32Decoder::unpack function, allowing remote attackers to inject fabricated point cloud data via malformed UDP packets.
date: "2026-08-17T20:50:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - iot
  - robotics
vendors:
  - TIER IV
products:
  - Nebula (1.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can exploit this by sending a malformed, short UDP datagram to the Velodyne sensor port.
    confidence_band: high
cves:
  - id: CVE-2026-74238
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74238
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Nebula to remediate CVE-2026-74238
      owner: IT Operations
      due: 72h
      evidence: NVD advisory confirms vulnerability in version 1.2.0
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Velodyne sensor ports via network ACLs
      owner: IT Operations
      addresses: CVE-2026-74238
      evidence: Nebula lacks sender-address restrictions
---

TIER IV Nebula versions up to and including 1.2.0 contain an out-of-bounds read vulnerability in the Vlp32Decoder::unpack() function. This vulnerability allows an unauthenticated remote attacker to trigger a read past the end of a UDP buffer by sending a maliciously crafted, short UDP datagram to the Velodyne sensor port. Because the service lacks sender-address restrictions, the decoder processes adjacent heap memory as part of the packet. These memory contents are then transformed into fabricated points and published into downstream PointCloud2 messages utilized by Autoware nodes. This exploitation can lead to the corruption of sensor perception data in autonomous vehicle systems, potentially impacting safety-critical decision-making processes.

## Impact

Successful exploitation results in the injection of garbage data into the perception pipeline of autonomous systems running the Nebula driver. This can lead to incorrect environment mapping or object detection errors. The vulnerability is specific to the Nebula middleware component used within the Autoware ecosystem, primarily impacting deployments that interface with Velodyne-compatible lidar sensors.

## Recommendation

Update the Nebula driver component to a version containing the patch for CVE-2026-74238. For organizations unable to immediately update, implement network-level access control lists (ACLs) on the gateway or vehicle network interface to restrict UDP traffic to the Velodyne sensor port to only known, authorized IP addresses.
