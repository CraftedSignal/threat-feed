---
brief_id: brief-2026-11-06-hisense-vidaa-auth-bypass
event_id: brief-2026-11-06-hisense-vidaa-auth-bypass
revision: 1
activity_at: "2026-11-06T21:28:58Z"
title: Hisense VIDAA Smart TV authentication bypass (CVE-2026-123998)
slug: 2026-11-hisense-vidaa-auth-bypass
description: Hisense VIDAA Smart TV firmware version V0000.01.00a.P0220 contains an authentication bypass in the MQTT broker on TCP port 36669, allowing unauthorized remote control via brute force or unauthenticated commands.
date: "2026-11-06T21:28:58Z"
type: advisory
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:hisense:vidaa_smart_tv_firmware:v0000.01.00a.p0220:*:*:*:*:*:*:*
vendors:
  - Hisense
products:
  - VIDAA Smart TV firmware (V0000.01.00a.P0220)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.001
    technique_name: Password Guessing
    evidence: The lack of rate limiting on the 4-digit pairing PIN allows for rapid brute-force attacks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker with LAN access can exploit this to perform unauthorized actions such as injecting key events, changing system settings, and launching installed applications.
    confidence_band: high
cves:
  - id: CVE-2026-123998
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123998
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  hunt_leads:
    - lead: Identify rapid connection attempts to TCP port 36669 from internal devices
      technique_id: T1110.001
      data_needed:
        - Firewall or switch flow logs showing TCP 36669 activity
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The service... accepts publicly documented default credentials... allowing a brute force of the entire code space in about five seconds.
  mitigation_plan:
    - priority: immediate
      action: Isolate affected TVs on a restricted VLAN without access to sensitive internal networks
      owner: IT Operations
      addresses: CVE-2026-123998
      evidence: The vulnerability poses a significant risk in hotel deployments where untrusted LAN access is common.
---

Hisense VIDAA Smart TV firmware V0000.01.00a.P0220 contains an authentication bypass vulnerability in its remote-control MQTT broker on TCP port 36669. The service accepts default credentials and an ineffective 4-digit pairing PIN with no rate limiting or account lockout, allowing the entire code space to be brute-forced in approximately five seconds. Furthermore, specific control actions require no authentication at all.

## Impact

A LAN-adjacent attacker can perform unauthorized actions, including injecting key events, changing volume, switching input sources, enumerating inputs, and launching arbitrary installed applications. The vulnerability poses a significant risk in deployments such as hotels where untrusted devices share a local network.

## Recommendation

- Perform network segmentation to isolate Smart TVs from primary corporate or guest data networks.
- Disable remote control features if not required by the specific deployment.
- Monitor for high-frequency traffic directed toward TCP port 36669 originating from non-authorized devices.
