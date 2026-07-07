---
title: Budibase Arbitrary File Read Vulnerability via PWA-zip Symlink Upload (CVE-2026-54352)
slug: 2026-07-budibase-arbitrary-file-read
description: A critical vulnerability, CVE-2026-54352, in Budibase server allows an authenticated workspace builder to perform arbitrary file reads on the host system by uploading a crafted PWA zip file containing a symbolic link, leading to credential compromise and privilege escalation, potentially enabling a full global administrator takeover.
date: "2026-07-03T11:01:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:budibase:budibase:*:*:*:*:*:*:*:*
tags:
  - arbitrary-file-read
  - web-vulnerability
  - privilege-escalation
  - credential-access
  - symlink
  - budibase
  - cloud
  - saas
vendors:
  - Budibase
products:
  - Budibase server < 3.39.9
  - '@budibase/server < 3.39.9'
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'Disclosure of `/data/.env`: `JWT_SECRET`, `INTERNAL_API_KEY`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `REDIS_PASSWORD`, `COUCHDB_PASSWORD`, `LITELLM_MASTER_KEY`, `DATABASE_URL`. Disclosure of `/etc/passwd` and `/etc/shadow` via the same primitive when the container runs as `root` (the shipped default).'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: 'HS256 JWT forge with the leaked `JWT_SECRET` against any user id, including the global admin: scope-changing escalation from workspace-builder to global-admin.'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: a workspace-level builder reads any file the server process can open (root inside the default Docker image, including `/data/.env` with `JWT_SECRET`, `INTERNAL_API_KEY`, `MINIO_*`, `REDIS_PASSWORD`, `COUCHDB_PASSWORD`, `DATABASE_URL`) by uploading one crafted PWA zip.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'the response of the asset-fetch endpoint returns those bytes verbatim... Live-verified: the response body of the asset-fetch endpoint is byte-identical to `docker exec budibase cat /data/.env`'
    confidence_band: high
cves:
  - id: CVE-2026-54352
    cvss: 9.6
    epss: 0.00494
references:
  - https://github.com/advisories/GHSA-w7mq-r738-x278
iocs:
  - type: file_path
    value: /data/.env
  - type: file_path
    value: /etc/passwd
  - type: file_path
    value: /etc/shadow
ioc_counts:
  file_path: 3
---

A critical arbitrary file read vulnerability (CVE-2026-54352) affects Budibase server versions up to `3.39.0` (HEAD `feab995`, released 2026-05-20). This flaw allows an authenticated workspace builder to read any file accessible by the server process, including highly sensitive configuration files like `/data/.env` (containing `JWT_SECRET`, `INTERNAL_API_KEY`, and database credentials) and system files such as `/etc/passwd` or `/etc/shadow`. The vulnerability stems from improper handling of symbolic links within uploaded PWA `.zip` files by the `extract-zip@2.0.1` library, coupled with insufficient validation in Budibase's icon processing logic. When exploited, it can lead to credential disclosure, privilege escalation to global administrator, and even cross-tenant exposure in multi-tenant environments. This vulnerability impacts self-hosted Budibase deployments, especially those running the default Docker image where the Node server executes as `root`.

## Attack Chain

1.  An attacker gains authenticated access as a workspace builder to a Budibase instance, obtaining necessary cookies and CSRF tokens from `GET /api/global/self`.
2.  The attacker crafts a `.zip` archive containing a symbolic link, for example, `evil.png`, which targets a sensitive file on the server's filesystem, such as `/data/.env`.
3.  The attacker includes an `icons.json` file within the `.zip` that references the created symbolic link, for example, `{"icons":[{"src":"evil.png", ...}]}`.
4.  The attacker sends an HTTP POST request to `/api/pwa/process-zip` with the crafted `.zip` file in the request body, using their authenticated session.
5.  The Budibase server, using `extract-zip@2.0.1`, extracts the `.zip` file into a temporary directory, preserving the absolute target of the symbolic link.
6.  During PWA icon processing, the server's validator (`packages/server/src/api/controllers/static/index.ts:259-268`) resolves the icon path, follows the symbolic link using `fs.existsSync`, and then opens the target file using `fsp.open` to stream its content.
7.  The content of the sensitive target file (e.g., `/data/.env`) is then streamed into MinIO and made available via a new public URL, typically `GET /api/assets/{appId}/pwa/{uuid}.png`.
8.  The attacker retrieves the sensitive file's content by making a GET request to the newly generated PWA asset URL, completing the arbitrary file read.

## Impact

Successful exploitation of CVE-2026-54352 leads to the disclosure of critical secrets from the Budibase server's host system. This includes `JWT_SECRET`, `INTERNAL_API_KEY`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `REDIS_PASSWORD`, `COUCHDB_PASSWORD`, and `DATABASE_URL` from the `/data/.env` file. With the leaked `JWT_SECRET`, an attacker can forge HS256 JWTs, escalating privileges from a workspace builder to a global administrator. This allows for full compromise of the Budibase instance, including potential cross-tenant data access on multi-tenant installations. Furthermore, if the Budibase Docker container runs as `root` (the default configuration), system files like `/etc/passwd` and `/etc/shadow` are also exposed, providing additional credential harvesting opportunities.

## Recommendation

*   Immediately update Budibase server to version `3.39.9` or newer to patch CVE-2026-54352.
*   Rotate all credentials found in `/data/.env`, including `JWT_SECRET`, `INTERNAL_API_KEY`, `MINIO_*`, `REDIS_PASSWORD`, `COUCHDB_PASSWORD`, and `DATABASE_URL`, especially if using self-hosted Budibase deployments.
*   Implement strong logging and monitoring for attempts to access sensitive file paths mentioned in the IOCs (e.g., `/data/.env`, `/etc/passwd`, `/etc/shadow`) via unexpected application endpoints.
*   Ensure that the Budibase server process does not run with `root` privileges within its container or host environment, following the principle of least privilege, to limit the blast radius of arbitrary file read vulnerabilities.
