---
brief_id: brief-2026-10-23-zimbra-lpe
event_id: brief-2026-10-23-zimbra-lpe
revision: 1
activity_at: "2026-10-23T15:07:55Z"
title: 'Zimbra Collaboration Suite: Local privilege escalation in zmmailboxdmgr (CVE-2026-50056)'
slug: 2026-10-zimbra-lpe
description: A local privilege escalation vulnerability in the Zimbra Collaboration Suite zmmailboxdmgr launcher allows the zimbra user to execute arbitrary commands as root via improper JVM argument validation in sudo.
date: "2026-10-23T15:07:55Z"
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
  - cpe:2.3:a:zimbra:collaboration_suite:10.1.16:*:*:*:*:*:*:*
  - cpe:2.3:a:zimbra:collaboration_suite:10.1.21:*:*:*:*:*:*:*
vendors:
  - Zimbra
products:
  - Zimbra Collaboration Suite (10.1.16, 10.1.21)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local privilege escalation vulnerability in the zmmailboxdmgr launcher of Zimbra Collaboration Suite (ZCS) allows the Unix zimbra account to execute arbitrary commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-50056
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50056
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit Zimbra installations for affected versions 10.1.16 and 10.1.21 and apply vendor patches
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-50056 specifically identifies these versions as vulnerable.
  hunt_leads:
    - lead: Search logs for zmmailboxdmgr executions containing heap-related JVM flags or OnOutOfMemoryError triggers
      technique_id: T1068
      data_needed:
        - Process creation events (Linux auditd or Sysmon for Linux)
        - Sudo execution logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves registering an OnOutOfMemoryError command in JVM arguments via the launcher.
  mitigation_plan:
    - priority: immediate
      action: Patch Zimbra Collaboration Suite to a version containing the fix for CVE-2026-50056
      owner: IT Operations
      addresses: CVE-2026-50056
      evidence: Official CVE entry for vulnerability.
---

CVE-2026-50056 is a local privilege escalation vulnerability in the `zmmailboxdmgr` utility within Zimbra Collaboration Suite (ZCS). The vulnerability originates from a passwordless sudo configuration that fails to restrict JVM arguments, allowing a low-privileged user (zimbra account) to inject malicious arguments. By forcing a heap exhaustion event during the JVM startup sequence, an attacker can execute arbitrary commands via the `OnOutOfMemoryError` handler while the process still maintains root privileges, prior to the intended privilege drop.

## Impact

Successful exploitation allows a local user already operating as the zimbra account to escalate privileges to root on the affected mailbox server. This bypasses security controls designed to drop privileges during the startup of the Jetty web container.

## Recommendation

1. Inventory all Zimbra Collaboration Suite mailbox server deployments to identify versions 10.1.16 and 10.1.21.
2. Prioritize patching or applying vendor-supplied mitigations for the affected versions immediately.
3. Until patched, monitor sudo logs and process creation patterns involving `zmmailboxdmgr` for unusual JVM arguments such as `-XX:OnOutOfMemoryError`.
