---
title: Argo CD Stored XSS in Application Link Annotations Enables Privilege Escalation
slug: 2026-05-argocd-xss-privesc
description: Argo CD is vulnerable to stored cross-site scripting (XSS) via manipulated application link annotations, allowing a low-privileged user to execute arbitrary JavaScript in a higher-privileged user's session, leading to privilege escalation.
date: "2026-05-19T15:57:01Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - privilege-escalation
  - argocd
  - cloud
vendors:
  - Argo Project
products:
  - Argo CD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-h98r-wv3h-fr38
  - CVE-2026-45738
rules:
  - title: Detect Argo CD Application Annotation XSS Attempt
    description: Detects attempts to inject JavaScript into Argo CD application annotations via kubectl annotate, potentially leading to XSS (CVE-2026-45738).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Argo CD API Session Userinfo Access
    description: Detects access to Argo CD API endpoint `/api/v1/session/userinfo` which can be used to exfiltrate user information during XSS attacks (CVE-2026-45738).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 2
---

Argo CD is vulnerable to a stored cross-site scripting (XSS) vulnerability (CVE-2026-45738) affecting versions prior to 2.14.21, versions 3.3.0-rc1 through 3.3.9, and versions 3.4.0-rc1 through 3.4.1. A user with application write access (developer role) can inject arbitrary JavaScript by crafting a malicious `link.argocd.argoproj.io/*` annotation value containing a `javascript:` URI. This occurs because the application summary tab renders these annotations as `<a href>` elements without proper URL validation, specifically missing a call to `isValidURL()`. When an administrator views the application summary and clicks the crafted link, the injected JavaScript executes within the administrator's authenticated session, enabling API exfiltration and privilege escalation. The default Content Security Policy provides no XSS mitigation, exacerbating the impact. This vulnerability was discovered and reported by Jan Kahmen of turingpoint.de.

## Attack Chain

1. An attacker with developer-level access to Argo CD identifies an application resource they can modify.
2. The attacker crafts a malicious annotation with a `link.argocd.argoproj.io/*` key and a value containing a `javascript:` URI, embedding malicious JavaScript code.
3. The attacker uses `kubectl annotate application <app-name> -n argocd 'link.argocd.argoproj.io/docs=GitHub Repo|javascript:fetch(...)'` to apply the annotation.
4. The annotation is stored within the Kubernetes Application resource.
5. A higher-privileged user (e.g., an administrator) navigates to the Argo CD UI and views the Summary tab of the modified application.
6. The malicious annotation is rendered as a seemingly legitimate link in the "URLs" section (e.g., "GitHub Repo").
7. The administrator clicks the link, triggering the execution of the embedded JavaScript code within their authenticated Argo CD session.
8. The JavaScript code exfiltrates sensitive information, such as session cookies or API tokens, or performs actions with administrator privileges against the Argo CD API, leading to privilege escalation.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-45738) in Argo CD can result in significant privilege escalation. An attacker with limited "developer" privileges can compromise an administrator's session. Because the injected link displays as any attacker-chosen text, the `javascript:` href is never visible to the victim, enabling maximum stealth. Any admin or operator who views the Summary tab of the compromised application is affected.

## Recommendation

*   Upgrade Argo CD to a patched version (>= 3.2.12, >= 3.3.10, >= 3.4.2) to remediate CVE-2026-45738.
*   Deploy the Sigma rule "Detect Argo CD Application Annotation XSS Attempt" to identify suspicious `kubectl annotate` commands modifying application annotations with `javascript:` URIs.
*   If upgrading is not immediately feasible, implement input validation on annotation values to prevent the injection of `javascript:` URIs, focusing on the `link.argocd.argoproj.io/*` annotations.
*   Monitor Kubernetes audit logs for unauthorized or suspicious modifications to Argo CD Application resources, specifically focusing on annotation changes.
