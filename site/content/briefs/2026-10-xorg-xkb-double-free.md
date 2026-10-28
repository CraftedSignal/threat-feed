---
brief_id: brief-2026-10-28-xorg-xkb-double-free
event_id: brief-2026-10-28-xorg-xkb-double-free
revision: 1
activity_at: "2026-10-28T02:16:18Z"
title: 'X.Org X Server and X Wayland: Double free vulnerability in XKB SetGeometry (CVE-2026-88812)'
slug: 2026-10-xorg-xkb-double-free
description: A double-free vulnerability in the XKB SetGeometry implementation in X.Org X Server and X Wayland allows local clients to cause a denial of service or potential arbitrary code execution.
date: "2026-10-28T02:16:18Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source analysis complete; no technical detection available without specialized memory or process-level debugging.
cpes:
  - cpe:2.3:a:x.org:x_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:x.org:xwayland:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - X.Org
products:
  - X Server (< 21.1.25)
  - X Wayland (< 24.1.14)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attached client can trigger this memory corruption flaw to cause a service crash (Denial of Service) or potentially achieve arbitrary code execution within the context of the X server process.
    confidence_band: high
cves:
  - id: CVE-2026-88812
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88812
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Monitor X server crash logs and process restart frequency
      technique_id: T1498
      data_needed:
        - systemd journal or syslog entries for xorg/xwayland
      priority: medium
      confidence: medium
      disposition: monitor-only
      evidence: The vulnerability can be used by attached clients to cause a crash.
  mitigation_plan:
    - priority: immediate
      action: Upgrade X.Org X Server to 21.1.25 and X Wayland to 24.1.14
      owner: IT Operations
      addresses: CVE-2026-88812
      evidence: Source explicitly identifies these versions as fixes.
---

CVE-2026-88812 is a memory corruption vulnerability involving a double-free condition in the XKB (X Keyboard Extension) SetGeometry implementation. This flaw affects versions of X.Org X Server prior to 21.1.25 and X Wayland prior to 24.1.14. An attacker with the ability to connect as a client to the X server can exploit this vulnerability to trigger a crash, resulting in a denial of service, or potentially gain arbitrary code execution within the context of the X server process.

## Impact

Successful exploitation may lead to a crash of the X server process (Denial of Service) or arbitrary code execution under the privileges of the X server instance.

## Recommendation

- Upgrade X.Org X Server to version 21.1.25 or later.
- Upgrade X Wayland to version 24.1.14 or later.
- Review system audit logs for repeated X server process restarts, which may indicate exploit attempts.
