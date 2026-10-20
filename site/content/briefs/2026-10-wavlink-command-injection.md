---
brief_id: brief-2026-10-20-wavlink-command-injection
event_id: brief-2026-10-20-wavlink-command-injection
revision: 1
activity_at: "2026-10-20T19:45:07Z"
title: 'Wavlink WL-WN530BE1-A: OS command injection via /protocol.csp (CVE-2026-113802)'
slug: 2026-10-wavlink-command-injection
description: Wavlink WL-WN530BE1-A firmware through version M30BE1_V251117 is vulnerable to unauthenticated remote code execution via an OS command injection flaw in the /protocol.csp endpoint.
date: "2026-10-20T19:45:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Checked against NVD details; needs environment validation
cpes:
  - cpe:2.3:o:wavlink:wl-wn530be1-a_firmware:*:*:*:*:*:*:*:*
vendors:
  - Wavlink
products:
  - WL-WN530BE1-A (<= M30BE1_V251117)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'A remote unauthenticated attacker can send a forged IP-FROM: 127.0.0.1 header to bypass login and execute arbitrary commands as root.'
    confidence_band: high
cves:
  - id: CVE-2026-113802
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113802
rules:
  - title: Detects CVE-2026-113802 Exploitation - OS Command Injection via /protocol.csp
    description: Detects exploitation attempts targeting CVE-2026-113802 by identifying suspicious file_id parameters containing shell metacharacters within /protocol.csp requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Wavlink WL-WN530BE1-A to a version containing the fix for CVE-2026-113802
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-113802 impact rating is 9.8
  mitigation_plan:
    - priority: immediate
      action: Apply firmware update or restrict access to management interface to trusted IP ranges
      owner: IT Operations
      addresses: CVE-2026-113802
      evidence: Vulnerability is exposed to remote unauthenticated attackers
---

Wavlink WL-WN530BE1-A firmware versions up to and including M30BE1_V251117 contain a critical OS command injection vulnerability, identified as CVE-2026-113802. The vulnerability exists within the sub_23B54 function of the ioos binary. This function improperly processes the file_id parameter when handling requests to the /protocol.csp endpoint with the option opt=ovpn_file and type=del. Because the input is passed directly to the popen() function without adequate sanitization, an attacker can supply shell metacharacters to execute arbitrary code. Furthermore, an attacker can bypass authentication requirements by forging the IP-FROM header to 127.0.0.1. Successfully exploiting this vulnerability allows an unauthenticated remote attacker to execute commands with root privileges on the affected networking device.

## Impact

Successful exploitation of CVE-2026-113802 grants an attacker full root-level control over the target Wavlink router. This impact includes the potential for full network traffic interception, modification of device configurations, persistent backdooring of the device firmware, and the ability to use the device as a pivot point for further lateral movement within the local area network.

## Recommendation

- Monitor for unauthorized HTTP requests to the /protocol.csp endpoint that include the opt=ovpn_file parameter.
- Implement network segmentation to isolate vulnerable networking hardware from sensitive segments of the internal network.
- Check for and apply firmware updates from Wavlink that remediate CVE-2026-113802.
- Use the provided Sigma rule to detect exploitation attempts targeting the identified vulnerable endpoint parameters.
