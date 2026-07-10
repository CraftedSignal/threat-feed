---
title: Langflow Unauthenticated Image Retrieval Vulnerability (CVE-2026-33484)
slug: 2024-01-langflow-unauth-image-retrieval
description: Langflow versions 1.0.0 through 1.8.1 are vulnerable to an unauthenticated image retrieval vulnerability (CVE-2026-33484) that allows attackers to download any user's uploaded images without credentials in multi-tenant deployments by accessing the `/api/v1/files/images/{flow_id}/{file_name}` endpoint.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - langflow
  - unauthenticated-access
  - image-retrieval
  - vulnerability
vendors:
  - Langflow
products:
  - Langflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33484
rules:
  - title: Detect Langflow Unauthenticated Image Retrieval Attempt
    description: Detects attempts to retrieve images without authentication from the Langflow `/api/v1/files/images/` endpoint, indicating potential exploitation of CVE-2026-33484.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Langflow API Flow ID Enumeration
    description: Detects potential flow ID enumeration by monitoring for suspicious patterns in API requests.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow, a tool used for building and deploying AI-powered agents and workflows, is susceptible to an unauthenticated image retrieval vulnerability. Specifically, versions 1.0.0 through 1.8.1 expose the `/api/v1/files/images/{flow_id}/{file_name}` endpoint without implementing any authentication or ownership validation. This oversight enables any unauthenticated user with knowledge of a `flow_id` and `file_name` to retrieve the corresponding image. In a multi-tenant Langflow deployment, this vulnerability permits an attacker who can discover or guess a valid `flow_id` (which the advisory notes can be leaked through other API responses) to download images uploaded by other users without providing any credentials. The vulnerability is identified as CVE-2026-33484, and a patch is available in version 1.9.0.

## Attack Chain

1.  Attacker identifies a Langflow instance running a vulnerable version (1.0.0 - 1.8.1).
2.  Attacker discovers a valid `flow_id`. This could occur through reconnaissance of API responses, error messages, or other information leakage.
3.  Attacker identifies or guesses the `file_name` of an image associated with the discovered `flow_id`.
4.  Attacker crafts an HTTP GET request to the vulnerable endpoint: `/api/v1/files/images/{flow_id}/{file_name}`, substituting the known `flow_id` and `file_name`.
5.  The Langflow server, lacking authentication or ownership checks, processes the request.
6.  The server responds with HTTP 200 and includes the requested image in the response body.
7.  Attacker downloads the image.
8.  Attacker potentially repeats the process with different `flow_id` and `file_name` combinations to exfiltrate additional images.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to potentially sensitive images uploaded by Langflow users. In a multi-tenant environment, this can lead to a significant breach of confidentiality, as attackers can access data belonging to other users without authentication. The observed damage includes unauthorized viewing and potential exfiltration of user data. The severity of the impact is dependent on the content of the images and the level of trust placed in the Langflow instance.

## Recommendation

*   Upgrade Langflow to version 1.9.0 or later to apply the patch for CVE-2026-33484.
*   Deploy the Sigma rule `Detect Langflow Unauthenticated Image Retrieval Attempt` to identify attempts to exploit this vulnerability in web server logs.
*   Monitor web server logs for requests to the `/api/v1/files/images/` endpoint, especially those lacking valid authentication tokens or session cookies.
