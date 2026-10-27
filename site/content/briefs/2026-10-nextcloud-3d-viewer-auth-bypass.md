---
brief_id: brief-2026-10-27-nextcloud-3d-viewer-auth-bypass
event_id: brief-2026-10-27-nextcloud-3d-viewer-auth-bypass
revision: 1
activity_at: "2026-10-27T18:04:46Z"
title: 'Nextcloud: 3D Viewer authentication bypass (CVE-2026-104189)'
slug: 2026-10-nextcloud-3d-viewer-auth-bypass
description: The 3D Viewer for Nextcloud application contains an authentication bypass vulnerability that allows unauthenticated users to access password-protected 3D model files via a valid share token.
date: "2026-10-27T18:04:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:nextcloud:3d_viewer:*:*:*:*:*:*:*:*
vendors:
  - Nextcloud
products:
  - 3D Viewer for Nextcloud (1.7.9-3.3.1)
cves:
  - id: CVE-2026-104189
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104189
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade 3D Viewer for Nextcloud to version 3.3.2
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in 3.3.2.
  hunt_leads:
    - lead: Identify unauthorized access to public 3D viewer endpoints
      technique_id: T1040
      data_needed:
        - Nextcloud web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Requests to GET /ocs/v2.php/apps/threedviewer/public/file/{token}/{fileId} returned 200 with the full file body for password-protected shares, with no password and no session.
  mitigation_plan:
    - priority: immediate
      action: Disable the 3D Viewer app via 'occ app:disable threedviewer'
      owner: IT Operations
      addresses: CVE-2026-104189
      evidence: As a workaround, disable the 3D Viewer app (occ app:disable threedviewer)... until you can upgrade.
---

Nextcloud 3D Viewer versions 1.7.9 through 3.3.1 contain an authentication bypass vulnerability (CVE-2026-104189) in the `PublicFileController`. The application fails to enforce share password requirements because the controller does not correctly implement `OCP\AppFramework\PublicShareController`, causing `PublicShareMiddleware` to skip authorization checks. Attackers with a known share token can access 3D files (such as STL, GLB/glTF, OBJ, STEP, and IFC) within password-protected links without providing the password. This issue is resolved in version 3.3.2.

## Impact

Successful exploitation allows unauthorized access to and exfiltration of 3D model files protected by password-restricted share links. Only 3D file formats supported by the application are affected.

## Recommendation

- Upgrade the 3D Viewer for Nextcloud to version 3.3.2 or later immediately.
- If upgrading is not immediately feasible, disable the 3D Viewer application using the command: `occ app:disable threedviewer`.
- Avoid relying on password protection for public shares containing sensitive 3D model files until the patch is applied.
