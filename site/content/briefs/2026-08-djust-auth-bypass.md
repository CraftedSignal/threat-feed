---
title: Authentication Bypass in djust LiveViewConsumer
slug: 2026-08-djust-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-55571) in the djust LiveViewConsumer allows unauthenticated attackers to execute event handlers on gated views by maintaining a WebSocket connection after a redirect.
date: "2026-08-25T18:50:53Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - djust
products:
  - djust (< 1.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authentication bypass vulnerability exists in the djust LiveViewConsumer component... an unauthenticated client to dispatch event-handler calls
    confidence_band: high
cves:
  - id: CVE-2026-55571
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-xx4j-w367-7247
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55571
---

CVE-2026-55571 affects the djust framework's `LiveViewConsumer` component, which handles LiveView mounts over WebSockets. In versions prior to 1.0.4, the framework fails to properly terminate a WebSocket connection when an authentication-gated view (e.g., using `login_required` or `on_mount` hooks) triggers a redirect. Instead of closing the socket and clearing the view instance, the server sends a navigate redirect frame and keeps the connection alive. 

An unauthenticated attacker using a raw WebSocket client can ignore the redirect frame and continue to send event-dispatching frames. Since the `handle_event` logic in these versions assumes the mount-time authentication checks are sufficient, it fails to re-verify the session status, allowing for the execution of sensitive event handlers. This bypass is critical for applications that rely solely on mount-level decorators and do not perform independent authorization checks inside individual event handler methods.

## Attack Chain

1. Attacker initiates an unauthenticated WebSocket connection to a `LiveView` endpoint protected by `login_required`.
2. Server's `LiveViewConsumer` performs the mount check and triggers a redirect response (navigate frame) due to missing authentication.
3. Attacker's custom WebSocket client parses the redirect frame but intentionally refuses to close the connection or navigate away.
4. Server keeps the underlying WebSocket connection open and fails to clear `self.view_instance` from memory.
5. Attacker sends a malformed `{"type":"event", ...}` frame targeting an `@event_handler` on the gated view.
6. The `LiveViewConsumer` processes the event frame, bypassing any further security checks, and invokes the target method.
7. The application logic executes the sensitive handler with an unauthenticated session, resulting in unauthorized data access or state mutation.

## Impact

Successful exploitation allows unauthenticated users to invoke sensitive server-side functions within gated views. Impact ranges from unauthorized information disclosure to data manipulation depending on the functionality of the exposed event handlers. Exploitation requires knowledge of specific view paths and event handler names. All djust applications using gated LiveViews on versions prior to 1.0.4 are affected.

## Recommendation

* Update to djust version 1.0.4 or later immediately to apply the patch provided in commit `1ae8aa9`.
* For legacy deployments where patching is not immediately possible, implement explicit authentication and authorization checks at the top of every `@event_handler` within gated views.
* Enable the defense-in-depth configuration `LIVEVIEW_CONFIG['reauth_on_event'] = True` to mandate session re-verification for all event handlers in gated views.
* Audit application code for LiveView event handlers that perform mutations without secondary validation against the current session user.
