---
title: Remote Command Execution Vulnerability in HPE Rack Management Controller
slug: 2026-10-hpe-rmc-rce
description: A critical vulnerability, CVE-2026-76740, in HPE Compute Scale-up and Superdome Flex servers allows unauthenticated remote attackers to execute arbitrary commands via the Rack Management Controller (RMC).
date: "2026-10-19T09:04:47Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - HPE
products:
  - Compute Scale-up Server 3200
  - Compute Scale-up Server 3250
  - Superdome Flex
  - Superdome Flex 280
cves:
  - id: CVE-2026-76740
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76740
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Isolate HPE RMC interfaces to dedicated management VLANs to prevent remote internet access
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76740 allows remote exploitation of the RMC.
  mitigation_plan:
    - priority: immediate
      action: Review vendor advisories and apply latest firmware updates to all affected Superdome and Compute Scale-up hardware
      owner: IT Operations
      addresses: CVE-2026-76740
      evidence: Source documentation requires firmware remediation for CVE-2026-76740.
---

CVE-2026-76740 is a high-severity security vulnerability affecting the Rack Management Controller (RMC) within several HPE enterprise server platforms, specifically the Compute Scale-up Server 3200 and 3250, as well as the Superdome Flex and Superdome Flex 280. The vulnerability allows a remote, unauthenticated attacker to inject and execute arbitrary commands directly on the RMC interface. Because the RMC is responsible for low-level server management, including power control, hardware monitoring, and remote console access, successful exploitation provides an attacker with significant control over the physical server infrastructure, bypassing standard operating system-level security controls. Defenders should prioritize auditing access to these management interfaces and ensuring that RMC management networks are logically isolated from general-purpose network traffic.

## Impact

Successful exploitation of this vulnerability enables full unauthorized control of the server's management interface. This can lead to persistent backdooring of the server hardware, data exfiltration from management logs, disruption of critical business services through unauthorized power cycles, or the deployment of persistent firmware-level threats that remain undetected by standard endpoint security solutions.

## Recommendation

- Identify all instances of HPE Compute Scale-up Server 3200, 3250, Superdome Flex, and Superdome Flex 280 in the environment.
- Restrict network access to the Rack Management Controller (RMC) ports to only allow connections from authorized management subnets or jump servers.
- Monitor logs for unusual traffic patterns or unauthorized login attempts targeting the management IP addresses associated with these specific HPE server models.
- Consult the official HPE security portal for patch availability and apply firmware updates to remediate CVE-2026-76740 as soon as they become available.
