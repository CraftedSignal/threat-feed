---
brief_id: brief-2026-10-27-dahua-p2p-hijacking
event_id: brief-2026-10-27-dahua-p2p-hijacking
revision: 4
activity_at: "2026-10-28T03:18:17Z"
revision_history:
  - revision: 2
    at: "2026-10-27T10:08:26Z"
    checksum: sha256:5c11cd5711fd9c3832edb88f44b36f196f3e6cc469b95b86464e3ea74686f5de
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
  - revision: 3
    at: "2026-10-27T10:24:14Z"
    checksum: sha256:bbcd8a8ef2357362e99b55330843dcb4c138ed1b02d7f45109332092cbd974d6
    summary: new IOCs
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
  - revision: 4
    at: "2026-10-28T03:18:17Z"
    checksum: sha256:f531fa0275d447f0c6200a5d775b977f71c54df470e46af072c614fe2cc805c4
    summary: new IOCs
    changed_fields:
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
title: 'Dahua IP cameras and recorders: P2P cloud access hijacking'
slug: 2026-10-dahua-p2p-hijacking
description: Attackers are hijacking Dahua IP cameras and recorders via the Easy4IP P2P cloud access feature by using brute-force attacks or exploiting CVE-2021-33044 and CVE-2021-33045 to gain unauthorized device control.
date: "2026-10-27T08:32:13Z"
lastmod: "2026-10-28T03:17:37Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:dahuatech:*:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:ipc-hum7xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:ipc-hx3xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:ipc-hx5xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd1a1_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd22_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd49_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd50_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd52c_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:sd6al_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-bf1241_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-bf2221_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-bf5x01_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-pt8x21b_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-sd2221_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-sd8x21_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:vto-65xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:vto-75x95x_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:vth-542xh_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:tpc-bf5x21_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:nvr-1xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:nvr-2xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:nvr-4xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:nvr-5xxx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:nvr-6xx_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-4x04_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-4x08_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-4x04_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-5x04_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-5x08_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-5x16_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-7x16_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:dahuasecurity:xvr-7x32_firmware:*:*:*:*:*:*:*:*
tags:
  - dahua
  - iot
  - auth-bypass
  - cisa-kev
  - ukraine
vendors:
  - Dahua
products:
  - IP cameras (all firmware < fixes for CVE-2021-33044/45)
  - NVRs (all firmware < fixes for CVE-2021-33044/45)
  - DVRs (all firmware < fixes for CVE-2021-33044/45)
  - IP cameras
  - NVRs
  - DVRs
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: attackers attempt to authenticate to the device management service using common/default credentials or by chaining CVE-2021-33044 and CVE-2021-33045
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078.001
    technique_name: Default Accounts
    evidence: A backdoor account (p2pwn / p2password) was left on 1,923 cameras.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The main way in is Dahua P2P cloud access (Easy4IP), which reaches devices by serial number through the manufacturer cloud, bypassing NAT and firewalls.
    confidence_band: high
cves:
  - id: CVE-2021-33044
    cvss: 9.8
    epss: 0.99989
    kev_status: "false"
  - id: CVE-2021-33045
    cvss: 9.8
    epss: 0.99593
    kev_status: "false"
references:
  - https://itweek.com.ua/2026/10/26/zlovmysnyky-mozhut-otrymaty-kontrol-nad-kameramy-ta-videoreyestratoramy-dahua-cherez-hmarnyj-dostup/
  - https://hunt.io/blog/operation-cameraswarm-dahua-cameras-compromised
  - https://therecord.media/ukraine-cert-ua-warning-chinese-dahua-cameras-hacked
  - https://nvd.nist.gov/vuln/detail/CVE-2021-33044
  - https://nvd.nist.gov/vuln/detail/CVE-2021-33045
  - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
  - https://www.dahuasecurity.com/aboutUs/trustedCenter/details/582
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable P2P/Cloud access features on all Dahua surveillance hardware.
      owner: IT Operations
      due: 24h
      evidence: CERT-UA advises to turn off P2P/Cloud access if not needed.
    - action: Audit device user accounts for unexpected entries such as p2pwn.
      owner: SOC
      due: 48h
      evidence: Hunt.io observed backdoor accounts left on compromised cameras.
  hunt_leads:
    - lead: Inspect device audit logs for login events originating from 127.0.0.1.
      technique_id: T1078
      data_needed:
        - Dahua device internal audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Signs of compromise: unknown accounts, unexpected config changes or text overlays on video, and DVRIP logins from 127.0.0.1 in the audit log.'
  mitigation_plan:
    - priority: immediate
      action: Apply the latest firmware updates provided by Dahua to remediate CVE-2021-33044 and CVE-2021-33045.
      owner: IT Operations
      addresses: CVE-2021-33044, CVE-2021-33045
      evidence: Dahua advisory confirms patches exist for these vulnerabilities.
updates:
  - at: "2026-10-27T10:07:50Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
  - at: "2026-10-27T10:23:39Z"
    level: L1
    summary: new IOCs
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
  - at: "2026-10-28T03:17:37Z"
    level: L1
    summary: new IOCs
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/dahua-cameras-easy4ip-p2p-hijacking-ukraine-oct-2026
---

CERT-UA has identified an ongoing campaign where attackers exploit Dahua surveillance devices via the Easy4IP P2P cloud access service. Attackers leverage predictable serial number patterns to reach devices through the manufacturer’s cloud relay, bypassing NAT and firewall protections. Once access to the device management interface is obtained, attackers attempt to compromise the device using weak or default passwords, or by exploiting authentication bypass vulnerabilities CVE-2021-33044 and CVE-2021-33045 on unpatched firmware. Confirmed indicators of compromise include the presence of unknown user accounts, unauthorized changes to device configuration, and suspicious DVRIP login events originating from 127.0.0.1.

## Attack Chain
1. Serial Number Discovery: Attackers probe the Easy4IP P2P service by guessing or iterating through predictable device serial numbers.
2. Cloud Relay Traversal: Attackers utilize the P2P connection to communicate with the target device, effectively bypassing local network perimeter controls.
3. Authentication Attempt: Attackers attempt to authenticate to the device management service using common/default credentials or by chaining CVE-2021-33044 and CVE-2021-33045.
4. Device Compromise: Upon successful authentication, attackers gain administrative access to the device.
5. Persistence: Attackers create unauthorized backdoor accounts (e.g., "p2pwn") to maintain future access.
6. Impact: Attackers modify device settings, view video streams, and apply visual overlays to the video feed.

## Impact
Unauthorized access to surveillance video, loss of device configuration control, and potential use of cameras as entry points into internal network segments. CERT-UA has confirmed active hijacking and exploitation campaigns.

## Recommendation
- Disable P2P/Cloud Access immediately on all Dahua devices unless explicitly required for business operations.
- Patch all affected Dahua IP cameras, NVRs, and DVRs to the latest firmware to remediate CVE-2021-33044 and CVE-2021-33045.
- Audit existing device accounts and remove any unknown or unauthorized user entries.
- Isolate surveillance devices into a dedicated VLAN with restricted access to the internet and internal production networks.
