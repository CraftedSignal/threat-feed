---
title: Google Security Updates — July 2026
slug: 2026-07-google-security-updates
description: Roundup of Google security advisories published in July 2026.
date: "2026-07-03T10:41:13Z"
lastmod: "2026-07-24T13:24:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Google
  - Red Hat
  - Brave Software
  - Opera
  - Vivaldi Technologies
  - Microsoft
  - Mozilla
  - Splunk
  - Opera Software
  - Elastic
  - Kubernetes
  - OPPO
  - Cloudflare
  - Twilio
products:
  - golang.org/x/crypto/ssh (< 0.52.0)
  - golang.org/x/crypto/ssh < 0.52.0
  - golang.org/x/crypto/ssh/agent < 0.52.0
  - golang.org/x/image (< 0.41.0)
  - Chrome
  - Brave
  - Opera
  - Vivaldi
  - Microsoft Edge
  - Google Chrome
  - Brave Browser
  - Mozilla Firefox
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Opera Browser
  - Vivaldi Browser
  - Edge
  - Firefox
  - Chromium
  - Google Workspace
  - Google Drive
  - Google Docs
  - Google Sheets
  - Google Forms
  - Google Apps Script
  - Google Workspace Marketplace
  - Google Workspace Drive
  - GCP
  - Google Kubernetes Engine
  - GKE
  - GCP Audit Logs
  - Kubernetes API
  - Kubernetes
  - Google Cloud Platform
  - Google Kubernetes Engine (GKE)
  - Google Cloud Platform (GCP) Audit Logs
  - Android (<= 2026-07-06)
  - Dialogflow CX <= 2026-06-30
  - Cloud Run <= 2026-06-30
  - Chrome (< 150.0.7871.114)
  - Chrome (< 150.0.7871.115)
  - Google Chrome (for Windows and macOS < 150.0.7871.115)
  - Google Chrome (for Linux < 150.0.7871.114)
  - Google Cloud Platform (BigQuery)
  - Google Cloud Platform (Dataform)
  - Google Cloud Platform (Colab Enterprise)
  - Helm
  - CoreDNS
  - kube-dns
  - Google Cloud Platform IAM Custom Roles
  - Service Account
  - Android (4.2.2 through December 2023 patch)
  - OPPO A5 (CPH1931/CPH1943, Android 9, last patched ~2022)
  - Cloud Run
  - Google Cloud Platform (GCP)
  - kube-controller-manager
  - Google OAuth
  - Apps Script
  - Kubernetes API (TokenRequest)
  - Kubernetes API Server
  - Kubernetes Kubelet API
  - CertificateSigningRequest (CSR)
  - GCP Fleet integration
  - Kubernetes Engine
  - Google Ads Sync Accounts (MMC)
  - google.golang.org/grpc (< 1.82.1)
  - Chrome (< 150.0.7871.181)
  - Chrome (< 150.0.7871.182)
  - Cloudflare Workers
  - Twilio TURN
  - Google Chrome (< 150.0.7871.186)
  - Google Chrome (< 150.0.7871.187)
affected_os:
  - Windows
  - Linux
  - Android
  - macOS
  - Android 4.2.2
  - Android 9
cves:
  - id: CVE-2026-15899
    cvss: 9.6
    epss: 0.00306
  - id: CVE-2026-15901
    cvss: 9.6
    epss: 0.00328
  - id: CVE-2026-16413
  - id: CVE-2026-16414
    epss: 0.001
  - id: CVE-2026-16423
    cvss: 8.8
  - id: CVE-2026-15904
    cvss: 8.8
    epss: 0.00306
  - id: CVE-2026-15902
    cvss: 8.8
    epss: 0.00409
references:
  - https://github.com/advisories/GHSA-rm3j-f69w-wqmq
  - https://github.com/advisories/GHSA-vgwf-h737-ff37
  - https://github.com/advisories/GHSA-jppx-rxg9-jmrx
  - https://github.com/advisories/GHSA-q675-qj96-32m9
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/headless_browser_usage.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_browser_process_launched_with_unusual_flags.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_chromium_browser_no_security_sandbox_process.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_chromium_browser_with_custom_user_data_directory.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_copied_in_temp_dir.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_extension_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_localstate_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_login_data_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_disable_or_stop_browser_process.yml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/initial_access_google_workspace_login_impossible_travel.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/defense_evasion_google_workspace_new_oauth_login_from_third_party_application.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_api_access_granted_via_dwd.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/initial_access_object_copied_to_external_drive_with_app_consent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_application_added_to_google_workspace_domain.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/credential_access_google_workspace_drive_encryption_key_accessed_by_anonymous_user.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/defense_evasion_domain_added_to_google_workspace_trusted_domains.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/impact_google_workspace_mfa_enforcement_disabled.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_2sv_policy_disabled.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_password_policy_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_mfa_disabled_for_google_workspace_organization.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secret_access_suspicious_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secrets_list_unusual_source_asn.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_api_request_failure_burst.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_suspicious_self_subject_review.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_user_exec_into_pod.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_admission_webhook_created_or_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_cluster_admin_role_binding.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_excessive_linux_capabilities.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_pod_host_network.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_pod_host_pid.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_privileged_pod_created.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_sensitive_hostpath_volume.toml
  - https://cyber.gc.ca/en/alerts-advisories/android-security-advisory-july-2026-monthly-rollup-av26-662
  - https://www.darkreading.com/application-security/dialogflow-cx-rogue-agent-flaw-enabled-ai-chatbot-data-theft
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0848/
  - https://cyber.gc.ca/en/alerts-advisories/google-chrome-security-advisory-av26-679
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2297
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_rapid_secret_get_activity_against_multiple_objects.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/impact_gcp_gke_coredns_or_kube_dns_configuration_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_rbac_wildcard_elevation_on_existing_role.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/initial_access_gcp_iam_custom_role_creation.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_key_created_for_service_account.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_role_modified.toml
  - https://sploitus.com/exploit?id=D0DC4908-C0DC-539F-BC8B-A87CCD40BBFF&utm_source=rss&utm_medium=rss
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2347
  - https://cloud.google.com/blog/topics/threat-intelligence/exposed-cloud-functions-harden/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_role_binding_referencing_service_account.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_sensitive_role_created_or_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_service_account_modified_rbac_objects.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_suspicious_assignment_of_controller_service_account.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_unusual_sensitive_workload_modification.toml
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15904
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15899
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15901
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15902
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_service_account_token_created_via_tokenrequest.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_exposed_service_created_with_type_nodeport.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_api_proxy_to_node.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_api_request_impersonating_privileged_identity.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_ephemeral_container_added_to_pod.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_certificate_signing_request_self_approved.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_client_certificate_signing_request_created_or_approved.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_certificate_signing_request_api_client_signer_requested.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_pod_exec_cloud_instance_metadata.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_pod_exec_sensitive_file_access.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_pod_exec_curl_wget_https.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_pod_exec_potential_reverse_shell.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_anonymous_endpoint_permission_enumeration.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_anonymous_pod_create_update_patch.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_forbidden_request_from_unusual_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/initial_access_gcp_gke_anonymous_request_authorized.toml
  - https://cofense.com/blog/click-to-sync-from-google-ads-maintenance-notice-to-credential-theft
  - https://github.com/advisories/GHSA-hrxh-6v49-42gf
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0907/
  - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
  - https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0925/
iocs:
  - type: url
    value: https://www.recordedfuture.com/research/from-castleloader-to-castlerat-tag-150-advances-operations
  - type: url
    value: https://peter.sh/experiments/chromium-command-line-switches/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/browser_unusual_flag/castle_chrome_shell32.log
  - type: file_name
    value: Local State
  - type: file_name
    value: Login Data
  - type: file_path
    value: '*\temp\*'
  - type: url
    value: https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
  - type: file_path
    value: '*\AppData\Local\Google\Chrome\User Data\Default\Login Data'
  - type: url
    value: https://x.com/suyog41/status/1825869470323056748
  - type: url
    value: https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
  - type: domain
    value: apps.googleusercontent.com
  - type: url
    value: https://support.google.com/a/answer/175197
  - type: url
    value: https://support.google.com/a/answer/7587183
  - type: url
    value: https://support.google.com/a/answer/7061566
  - type: url
    value: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-google_workspace.html
  - type: url
    value: https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - type: url
    value: https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - type: url
    value: https://sploitus.com/exploit?id=D0DC4908-C0DC-539F-BC8B-A87CCD40BBFF
  - type: filename
    value: invoices.apk
  - type: url
    value: https://cloudrun01-abc.europe-west3.run.app/
  - type: other
    value: kubernetes.io/kube-apiserver-client
  - type: other
    value: system:kube-controller-manager
  - type: other
    value: system:masters
  - type: other
    value: system:admin
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: metadata.google.internal
  - type: domain
    value: enavalenceart[.]com
  - type: domain
    value: syncmcchub[.]blogspot[.]com
  - type: domain
    value: mcc-sync-ads[.]com
  - type: url
    value: https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_0256605430.html
  - type: url
    value: http://172.86.126.18:443/update_ms.msi
  - type: ip
    value: 172.86.126.18
  - type: file_name
    value: update_ms.msi
  - type: file_path
    value: C:\programdata\update_ms.msi
  - type: file_name
    value: lib.dll
  - type: product_name
    value: msaRAT
  - type: product_name
    value: Chaos ransomware
  - type: domain
    value: cloudflare.com
  - type: domain
    value: twilio.com
  - type: url
    value: https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_01320465736.html
ioc_counts:
  domain: 7
  file_name: 4
  file_path: 3
  filename: 1
  ip: 2
  other: 4
  product_name: 2
  url: 17
updates:
  - at: "2026-07-21T14:45:57Z"
    level: L1
    summary: new IOCs
    sources:
      - cofense
    source_urls:
      - https://cofense.com/blog/click-to-sync-from-google-ads-maintenance-notice-to-credential-theft
  - at: "2026-07-21T22:05:31Z"
    level: L2
    summary: added CVE-2026-15899 +3
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-hrxh-6v49-42gf
  - at: "2026-07-22T14:52:10Z"
    level: L2
    summary: added CVE-2026-16413 +2
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0907/
  - at: "2026-07-23T10:03:58Z"
    level: L2
    summary: added CVE-2026-15902 +1
    sources:
      - talos
    source_urls:
      - https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
  - at: "2026-07-24T13:24:01Z"
    level: L1
    summary: new IOCs
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0925/
---

Aggregated Google security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Google's July 2026 security updates.
