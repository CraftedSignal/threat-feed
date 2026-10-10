---
title: Denial of Service in Lenovo Power Management Driver (CVE-2025-9548)
slug: 2026-10-lenovo-pmdrvs-dos
description: An authenticated local user can trigger a system-wide denial of service by exploiting a null pointer dereference vulnerability in the Lenovo Power Management Driver, pmdrvs.sys.
date: "2026-10-10T17:00:20Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:lenovo:power_management_driver:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - windows
  - hardware-vulnerability
vendors:
  - Lenovo
products:
  - Power Management Driver (< 1.69.70.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The PoC tool is compiled as an executable and run from the Windows command line.
    confidence_band: high
cves:
  - id: CVE-2025-9548
    cvss: 5.5
    epss: 0.00119
references:
  - https://support.lenovo.com/us/en/product_security/LEN-203293
  - https://nvd.nist.gov/vuln/detail/CVE-2025-9548
  - https://sploitus.com/exploit?id=DF82A6EB-5C2D-55A8-877C-40C1AAFA7B2E
rules:
  - title: Detect Potential CVE-2025-9548 PoC Execution
    description: Detects execution of the CVE-2025-9548 PoC tool by monitoring process creation with command-line arguments matching the known trigger flags.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Lenovo Power Management Driver to 1.69.70.0
      owner: IT Operations
      due: 72h
      evidence: Lenovo advisory LEN-203293 states 1.69.70.0 as fixed version
    - action: Deploy Sigma detection rule for PoC usage
      owner: Detection Engineering
      due: 24h
      evidence: PoC trigger parameters documented in brief
  mitigation_plan:
    - priority: immediate
      action: Upgrade Power Management Driver to 1.69.70.0 or later
      owner: IT Operations
      addresses: CVE-2025-9548
      evidence: Vendor security advisory LEN-203293
---

CVE-2025-9548 is a null pointer dereference vulnerability residing in the Lenovo Power Management Driver (pmdrvs.sys) affecting versions prior to 1.69.70.0. The vulnerability allows an authenticated local user with sufficient privileges to send a crafted IOCTL request to the driver interface, triggering an unhandled exception that results in a system crash (Blue Screen of Death). The researcher, Sam Dalgleish, publicly released a proof-of-concept (PoC) tool on October 10, 2026, which demonstrates the ability to invoke the crash by sending IOCTL 0x802B2243 to the device object '\\.\pmdrvs'. While the vulnerability is limited to a local denial of service and does not inherently provide privilege escalation or arbitrary code execution, the availability of functional exploit code increases the risk for unpatched enterprise workstations and laptops.

## Impact

Successful exploitation results in an immediate system-wide denial of service, forcing a reboot and potential data loss for any user with active sessions. The vulnerability affects a broad range of Lenovo hardware utilizing the affected Power Management Driver versions.

## Recommendation

1. Patch all Lenovo systems immediately by upgrading the Power Management Driver to version 1.69.70.0 or later.
2. Audit high-availability or critical workstations for the presence of pmdrvs.sys versions earlier than 1.69.70.0.
3. Deploy detection logic to identify the execution of the identified PoC or similar attempts to interface with the vulnerable driver IOCTL interface.
