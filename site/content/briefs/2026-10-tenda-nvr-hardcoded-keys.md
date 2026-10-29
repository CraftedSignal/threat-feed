---
brief_id: brief-2026-10-29-tenda-nvr-hardcoded-keys
event_id: brief-2026-10-29-tenda-nvr-hardcoded-keys
revision: 1
activity_at: "2026-10-29T05:59:39Z"
title: 'Tenda NVR_4H: Hardcoded TLS private key vulnerability (CVE-2026-79551)'
slug: 2026-10-tenda-nvr-hardcoded-keys
description: Tenda NVR_4H firmware version V27.5.58.6 contains a hardcoded ECDSA private key and self-signed certificate in the read-only partition, enabling full TLS session interception via man-in-the-middle attacks.
date: "2026-10-29T05:59:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Environment validation required to confirm if local NVR_4H units are using the documented firmware.
cpes:
  - cpe:2.3:h:tenda:nvr_4h:v27.5.58.6:*:*:*:*:*:*:*
tags:
  - iot
  - cve
  - mitm
  - firmware
vendors:
  - Tenda
products:
  - NVR_4H (V27.5.58.6)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.004
    subtechnique_name: Private Keys
    evidence: The NVR_4H firmware stores an ECDSA key pair in its read-only user-x.squashfs partition... the private key in /etc/privkey.pem.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    subtechnique_id: T1557.001
    subtechnique_name: LLMNR/NBT-NS Poisoning and SMB Relay
    evidence: An attacker on the same network... can put a proxy between the admin's browser and the NVR via ARP spoofing or DNS poisoning.
    confidence_band: high
cves:
  - id: CVE-2026-79551
    cvss: 7.5
    epss: 0.003
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SNYI001-CVE-2026-79551-TENDA
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SNYI001-CVE-2026-79551-TENDA&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory Tenda NVR_4H devices and verify firmware version V27.5.58.6.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is limited to firmware version V27.5.58.6.
  hunt_leads:
    - lead: Monitor for suspicious ARP broadcast activity or localized DNS poisoning attempts targeting IP addresses associated with Tenda NVR infrastructure.
      technique_id: T1557.001
      data_needed:
        - Network ARP logs
        - DNS query logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An attacker on the same network... can put a proxy... via ARP spoofing or DNS poisoning.
  mitigation_plan:
    - priority: immediate
      action: Restrict management access to NVR units to a dedicated, isolated VLAN.
      owner: IT Operations
      addresses: CVE-2026-79551
      evidence: Confidentiality and integrity of the entire HTTPS management interface are lost... against anyone who has downloaded the public image.
---

Tenda NVR_4H network video recorders running firmware V27.5.58.6 include a static, hardcoded ECDSA private key and self-signed certificate within the read-only `user-x.squashfs` filesystem. Because this key is identical across all devices and is publicly accessible within the downloadable firmware image, any attacker can extract the private key. This allows an attacker on the same network to intercept, decrypt, and modify HTTPS management traffic without triggering browser warnings. The vulnerability is identified as CVE-2026-79551 and CNVD-2026-25884.

## Attack Chain

1. Attacker downloads the publicly available NVR_4H firmware image (V27.5.58.6) from Tenda.
2. Attacker unpacks the firmware container using standard tools (e.g., binwalk, unsquashfs).
3. Attacker extracts the hardcoded private key (`/etc/privkey.pem`) and certificate (`/etc/cacert.pem`) from the squashfs partition.
4. Attacker positions themselves on the network segment as the NVR_4H administrator (via ARP spoofing or DNS poisoning).
5. Attacker intercepts the TLS connection between the admin's browser and the NVR using the extracted private key to decrypt and present the legitimate-looking certificate.
6. Attacker performs real-time traffic manipulation to capture administrator credentials, session tokens, and camera RTSP credentials.
7. Attacker gains unauthorized administrative access to the recorder and connected surveillance cameras.

## Impact

Successful exploitation results in the complete loss of confidentiality and integrity for the HTTPS management interface. An attacker can perform a passive man-in-the-middle attack to harvest credentials or modify system configuration, granting full control over the surveillance infrastructure.

## Recommendation

- Identify all Tenda NVR_4H units within the environment and confirm their firmware version.
- Isolate vulnerable NVR_4H devices from untrusted network segments or external exposure until a patch is available.
- Implement strict network segmentation to minimize the risk of ARP spoofing or MITM attacks targeting management traffic.
- Monitor for unauthorized ARP traffic or anomalous network configuration changes within segments hosting NVR devices.
- Contact Tenda support to inquire about firmware updates or patches that remove the hardcoded key material and implement per-device provisioning.
