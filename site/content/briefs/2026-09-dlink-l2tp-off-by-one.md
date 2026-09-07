---
title: Remote Off-by-One Vulnerability in D-Link DIR-605 L2TP Parser
slug: 2026-09-dlink-l2tp-off-by-one
description: An off-by-one vulnerability in the L2TP Control Message Parser of D-Link DIR-605 routers allows remote attackers to trigger memory corruption via a malicious peer_hostname argument.
date: "2026-09-07T12:53:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:dlink:dir-605_firmware:b1v202wwb03:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DIR-605 (B1v202WWB03)
cves:
  - id: CVE-2026-86297
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86297
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block UDP port 1701 (L2TP) on internet-facing firewalls for affected D-Link devices.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable via the L2TP Control Message Parser.
  mitigation_plan:
    - priority: immediate
      action: Isolate or replace D-Link DIR-605 (B1v202WWB03) units until a firmware patch is released.
      owner: IT Operations
      addresses: CVE-2026-86297
      evidence: NVD vulnerability entry identifies target as D-Link DIR-605 B1v202WWB03.
---

A critical security flaw (CVE-2026-86297) has been identified in the D-Link DIR-605 router, specifically within the B1v202WWB03 firmware version. The vulnerability resides in the L2TP (Layer 2 Tunneling Protocol) Control Message Parser component, specifically within the `tunnel_set_params` function located in the file `progs.gpl/pppd.alpha/l2tp/tunnel.c`. An attacker can remotely exploit this by sending a crafted L2TP control message containing a malformed `peer_hostname` argument. This manipulation triggers an off-by-one error, potentially leading to memory corruption or instability in the device's control process. While the exploitation process is classified as highly complex and difficult to execute successfully, functional exploit code is publicly available, increasing the risk to exposed devices. Defenders should prioritize isolating affected D-Link devices or ensuring they are not reachable from untrusted networks, as L2TP is a common target for remote service exploitation.

## Impact

Successful exploitation of this vulnerability allows a remote, unauthenticated attacker to cause a denial-of-service condition or potentially execute arbitrary code on the affected D-Link router. Given that the device is a consumer-grade router, compromise could allow an attacker to intercept local network traffic, bypass authentication, or use the device as a pivot point for further lateral movement within the victim's internal network.

## Recommendation

Prioritize the decommissioning or network segmentation of D-Link DIR-605 routers running firmware version B1v202WWB03. Since no specific patch is documented, implement edge filtering to block unsolicited L2TP (UDP port 1701) traffic originating from the internet to internal assets. Monitor network telemetry for anomalous L2TP control packets that exhibit unusually long or malformed hostname fields.
