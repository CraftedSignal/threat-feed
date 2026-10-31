---
brief_id: brief-2026-10-31-grafana-auth-bypass
event_id: brief-2026-10-31-grafana-auth-bypass
revision: 1
activity_at: "2026-10-31T10:15:50Z"
title: 'Grafana Alerting: Authorization bypass via schema downgrade (CVE-2026-100105)'
slug: 2026-10-grafana-auth-bypass
description: CVE-2026-100105 is an authorization bypass in Grafana Alerting Contact Points that allows attackers with Editor permissions to redirect alert notifications to unauthorized destinations and exfiltrate credentials through schema version manipulation.
date: "2026-10-31T10:15:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
vendors:
  - Grafana
products:
  - Grafana OSS (< 12.4.14, 13.0.12, 13.1.9, 13.2.5)
  - Grafana Enterprise (< 12.4.14, 13.0.12, 13.1.9, 13.2.5)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048.003
    technique_name: Exfiltration Over Unencrypted Non-C2 Protocol
    evidence: Grafana dispatches the notification to the ATTACKER URL, including credentials.
    confidence_band: high
cves:
  - id: CVE-2026-100105
    cvss: 7.7
    epss: 0.0029
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=8BCA6340-2BFB-5B6C-9060-C4A1612B858C
  - https://github.com/grafana/alerting/security/advisories/GHSA-92gx-p2qg-82fw
  - https://sploitus.com/exploit?id=8BCA6340-2BFB-5B6C-9060-C4A1612B858C&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: http://collector:9001/exfil
ioc_counts:
  url: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Grafana instances to the patched versions.
      owner: IT Operations
      due: 24h
      evidence: Fixed versions 12.4.14, 13.0.12, 13.1.9, 13.2.5
  hunt_leads:
    - lead: Audit alert receivers for non-current schema versions.
      technique_id: T1565
      data_needed:
        - Grafana API response for /apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Audit receivers for non-current schema versions: any integration with version != ''v1'' deserves review.'
---

CVE-2026-100105 (GHSA-92gx-p2qg-82fw) is a high-severity authorization bypass vulnerability in Grafana OSS and Enterprise versions 12.4.x, 13.0.x, 13.1.x, and 13.2.0 - 13.2.4. The vulnerability arises because sensitive fields in alert notification integrations (such as the webhook destination URL) are protected by RBAC logic that validates configuration changes against a schema. By switching an integration to a legacy schema version (`v0mimir1`), the protection logic is bypassed because the URL field is not marked as protected in the legacy schema definition.

A researcher also identified two additional authorization weaknesses (Zero-day findings A and B) that remain reproducible on the fully patched version 13.2.5. These affect the `ReceiverTestingService` subresource, allowing attackers to exfiltrate stored credentials (e.g., Basic Auth headers) and dispatch notifications to unauthorized URLs without requiring persistent modification to stored receivers.

## Attack Chain

1. Attacker (with Editor role) enumerates existing alert receivers via GET /apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers.
2. Attacker selects a target receiver and prepares a PUT request to update its configuration.
3. Attacker embeds a schema downgrade in the request by setting the integration version to a legacy identifier (e.g., v0mimir1).
4. Attacker includes an arbitrary attacker-controlled destination URL in the settings object.
5. The Grafana backend evaluates the protected-field diff against the legacy schema version, which fails to trigger the authorization check.
6. The system updates the stored receiver configuration with the attacker's malicious destination URL.
7. Attacker triggers a notification (via the test subresource or actual alert firing) to exfiltrate alert payloads or stored credentials to their infrastructure.

## Impact

Successful exploitation allows for the silent exfiltration of alert payloads and sensitive notification credentials (e.g., tokens, API keys, Basic Auth credentials) to attacker-controlled infrastructure. This risk persists after patching for receivers that were already downgraded while the instance was unpatched.

## Recommendation

- Upgrade to Grafana OSS or Enterprise versions 12.4.14, 13.0.12, 13.1.9, or 13.2.5 immediately.
- After upgrading, audit all existing alert receivers for legacy or non-standard schema versions (`version != "v1"` for webhooks) and verify that their destination URLs are legitimate.
- Monitor logs for unusual sequences of `PUT` requests to receiver configuration endpoints followed by `POST` requests to receiver-test subresources from non-administrative users.
