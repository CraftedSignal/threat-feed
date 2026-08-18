---
title: GeoLens Multiple Authorization Bypass Vulnerabilities
slug: 2026-08-geolens-auth-bypass
description: GeoLens versions prior to 1.2.3 contain multiple authorization bypass vulnerabilities allowing unauthenticated or low-privileged users to access private dataset metadata, schema, rows, and raster/vector tile data.
date: "2026-08-18T20:57:53Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - GeoLens
products:
  - GeoLens
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The most severe instances require no authentication at all (anonymous, network-only) to disclose private dataset metadata and schema.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The authorize the URL resource, read a different dataset un-re-authorized pattern let callers read data from datasets they have no access to.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p23g-mvhj-jh3j
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55178
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all GeoLens deployments to version 1.2.3.
      owner: IT Operations
      due: 24h
      evidence: All issues are fixed in 1.2.3. There is no complete configuration workaround.
  hunt_leads:
    - lead: Identify anonymous access to private datasets via /maps/ or /collections/datasets/items
      technique_id: T1068
      data_needed:
        - Web server logs
        - API gateway access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Finding 1 and Finding 3 document anonymous metadata disclosure via these endpoints.
---

GeoLens versions prior to 1.2.3 are affected by multiple authorization bypass vulnerabilities (CVE-2026-55178) arising from a failure to perform re-authorization checks when accessing secondary datasets. The software incorrectly validates only the primary resource requested in the URL, failing to verify user permissions for referenced objects such as map layers, dataset relationships, VRT mosaic members, OGC catalog entries, and AI metadata request bodies. 

These flaws enable unauthenticated attackers or users with low-privileged 'editor' roles to exfiltrate sensitive data, including feature geometries, raster pixels, table rows, and detailed dataset metadata. The vulnerabilities impact the core API, including OGC endpoints and AI-assisted processing tools. Because these issues exist within the application logic and are reachable via network access, there are no comprehensive configuration-based workarounds. Organizations must upgrade to version 1.2.3, which introduces proper dataset-level access control checks (e.g., 'can_access_dataset') across all affected service endpoints.

## Attack Chain

1. Attacker identifies a target GeoLens instance reachable over the network.
2. Attacker crafts a GET request to `/maps/{id}` or a POST request to `/ai/metadata/` targeting a specific resource.
3. Attacker references an unauthorized, private dataset identifier within the request body or as a layer reference.
4. The GeoLens API authorizes the primary map or session but fails to validate the user's access to the referenced secondary dataset.
5. The API processes the request, incorporating internal dataset information (schema, rows, or sample values) into the response.
6. The sensitive dataset data is returned to the attacker in the HTTP response payload.
7. For vector data, the attacker extracts an HMAC-signed tile URL and replays it to the tile endpoint to bypass further checks.
8. Final objective of data exfiltration is achieved without requiring authentication or elevated privileges.

## Impact

Successful exploitation allows unauthorized access to private dataset metadata, including column schemas, sampled row values, contact information, and source URLs. Attackers can exfiltrate full raster pixel data, vector feature geometries, and underlying database rows. These vulnerabilities affect all GeoLens deployments using versions prior to 1.2.3, spanning across PyPI, npm, and container-based distributions.

## Recommendation

* Immediately upgrade all GeoLens instances to version 1.2.3 to patch CVE-2026-55178.
* Audit access logs for anomalous, high-frequency GET requests to /maps/ or /collections/datasets/items that do not correspond to known user navigation patterns.
* Restrict network exposure of the GeoLens API, particularly for instances containing sensitive or private raster and vector datasets.
* Avoid co-locating highly sensitive private datasets within the same map or VRT projects alongside public-facing resources while the patching process is ongoing.
