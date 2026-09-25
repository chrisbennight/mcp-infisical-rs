# Generated catalog summary

Generated from the executable `operation_policy` and `server_capabilities` exports.
Run `python3 scripts/catalog_summary.py --write` to regenerate; ordinary
documentation validation checks this file for drift.

Schema revision: `2026-09-25.6`. Pinned upstream: `0.160.12`.

This build serves **234 operations**. The separate capability ledger has
**169 implemented** and
**70 unavailable** entries. Ledger entries
describe capabilities and are not a count of callable operations.

These are build facts. Check the instance's `server.capabilities` and
`operations.describe` for its profile and delivery prerequisites. Upstream
permissions and edition entitlement are not probed by these exports. See
[task guides](tasks.md), [operation policy](operation-policy.md), and
[API coverage](api-coverage.md) for those separate decisions.

## Executor classes

| Executor | Operations |
| --- | ---: |
| `infisical.read` | 38 |
| `infisical.readAudited` | 66 |
| `infisical.write` | 67 |
| `infisical.destroy` | 63 |

Audited reads, mutation classes, destructive effects, credential disclosure,
and confirmation fields are separate policy facts. A class is not caller
authorization and does not prove every action changes durable configuration.

## Startup profile membership

| Profile | Enabled operations |
| --- | ---: |
| `metadata` | 96 |
| `secrets` | 55 |
| `pkiSsh` | 101 |
| `full` | 234 |

## Domain and delivery facts

The domain is the first component of the exported name. Secret delivery counts
identify operations with a `delivery` argument; actual reference availability
depends on the instance. Every executor also supports whole-result file delivery
when the file plane is enabled. Inline errors remain inline.

| Domain | Operations | May disclose credentials | Secret delivery argument | Requires file plane | Implemented ledger entries | Unavailable ledger entries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `admin` | 0 | 0 | 0 | 0 | 0 | 1 |
| `appConnections` | 6 | 0 | 0 | 0 | 3 | 1 |
| `auditLogs` | 1 | 0 | 0 | 0 | 1 | 0 |
| `certificateAuthorities` | 15 | 0 | 0 | 0 | 5 | 6 |
| `certificatePolicies` | 5 | 0 | 0 | 0 | 4 | 0 |
| `certificateProfiles` | 9 | 2 | 2 | 0 | 7 | 0 |
| `certificateRequests` | 4 | 1 | 1 | 0 | 3 | 0 |
| `certificateSyncs` | 0 | 0 | 0 | 0 | 0 | 1 |
| `certificateTemplates` | 0 | 0 | 0 | 0 | 0 | 1 |
| `certificates` | 11 | 4 | 4 | 1 | 7 | 0 |
| `codeSigners` | 23 | 0 | 0 | 0 | 22 | 2 |
| `dynamicSecretLeases` | 5 | 1 | 1 | 0 | 4 | 1 |
| `dynamicSecrets` | 5 | 0 | 0 | 0 | 4 | 2 |
| `environments` | 6 | 0 | 0 | 0 | 5 | 0 |
| `events` | 0 | 0 | 0 | 0 | 0 | 1 |
| `externalMigrations` | 0 | 0 | 0 | 0 | 0 | 1 |
| `folders` | 6 | 0 | 0 | 0 | 5 | 0 |
| `groups` | 4 | 0 | 0 | 0 | 1 | 1 |
| `identities` | 5 | 0 | 0 | 0 | 4 | 1 |
| `identityAliCloudAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityAwsAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityAzureAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityGcpAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityJwtAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityKubernetesAuth` | 4 | 0 | 0 | 0 | 4 | 3 |
| `identityLdapAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityOciAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityOidcAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityProjectAdditionalPrivileges` | 6 | 0 | 0 | 0 | 4 | 0 |
| `identitySpiffeAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityTlsCertificateAuth` | 0 | 0 | 0 | 0 | 0 | 1 |
| `identityTokenAuth` | 9 | 1 | 1 | 0 | 8 | 1 |
| `identityUniversalAuth` | 9 | 1 | 1 | 0 | 8 | 1 |
| `integrations` | 0 | 0 | 0 | 0 | 0 | 1 |
| `kms` | 15 | 3 | 3 | 0 | 10 | 1 |
| `organizationGroupMemberships` | 0 | 0 | 0 | 0 | 0 | 1 |
| `organizationRoles` | 2 | 0 | 0 | 0 | 1 | 1 |
| `organizationScim` | 0 | 0 | 0 | 0 | 0 | 1 |
| `organizationSso` | 0 | 0 | 0 | 0 | 0 | 1 |
| `organizations` | 0 | 0 | 0 | 0 | 0 | 2 |
| `pkiAlerts` | 0 | 0 | 0 | 0 | 0 | 1 |
| `pkiCollections` | 0 | 0 | 0 | 0 | 0 | 1 |
| `pkiDiscovery` | 0 | 0 | 0 | 0 | 0 | 1 |
| `pkiInstallations` | 0 | 0 | 0 | 0 | 0 | 1 |
| `projectGroupMemberships` | 2 | 0 | 0 | 0 | 1 | 1 |
| `projectIdentityMemberships` | 5 | 0 | 0 | 0 | 4 | 0 |
| `projectMemberships` | 0 | 0 | 0 | 0 | 0 | 1 |
| `projectRoles` | 2 | 0 | 0 | 0 | 1 | 1 |
| `projectTemplates` | 0 | 0 | 0 | 0 | 0 | 1 |
| `projectUserMemberships` | 5 | 0 | 0 | 0 | 4 | 0 |
| `projects` | 5 | 0 | 0 | 0 | 4 | 0 |
| `secretImports` | 5 | 0 | 0 | 0 | 5 | 2 |
| `secretMetadata` | 0 | 0 | 0 | 0 | 1 | 0 |
| `secretRotations` | 10 | 1 | 1 | 0 | 5 | 1 |
| `secretScanning` | 0 | 0 | 0 | 0 | 0 | 1 |
| `secretSyncs` | 7 | 0 | 0 | 0 | 3 | 3 |
| `secretVersions` | 0 | 0 | 0 | 0 | 0 | 1 |
| `secrets` | 8 | 1 | 1 | 0 | 7 | 2 |
| `serviceTokens` | 0 | 0 | 0 | 0 | 0 | 1 |
| `sharedSecrets` | 0 | 0 | 0 | 0 | 0 | 1 |
| `sshCertificateAuthorities` | 7 | 0 | 0 | 0 | 4 | 0 |
| `sshCertificateTemplates` | 5 | 0 | 0 | 0 | 4 | 0 |
| `sshCertificates` | 2 | 1 | 1 | 0 | 2 | 0 |
| `sshHostGroups` | 8 | 0 | 0 | 0 | 5 | 0 |
| `sshHosts` | 8 | 0 | 0 | 0 | 5 | 2 |
| `subOrganizations` | 0 | 0 | 0 | 0 | 0 | 1 |
| `tags` | 5 | 0 | 0 | 0 | 4 | 0 |
| `userProjectAdditionalPrivileges` | 0 | 0 | 0 | 0 | 0 | 2 |
| `users` | 0 | 0 | 0 | 0 | 0 | 1 |
| `webhooks` | 0 | 0 | 0 | 0 | 0 | 1 |

## Unavailable compiled capabilities

This list preserves each exported reason. Edition-gated and deferred API routes
are classified separately in the coverage matrix; availability here does not
establish licensing, caller permission, or deployment readiness.

| Capability | Reason |
| --- | --- |
| `admin.bootstrap` | instance bootstrap is an out-of-band one-time operation and is not reachable through the management server |
| `appConnections.otherProviders.admin` | provider-tagged administration is currently implemented only for the pinned GitHub contract |
| `certificateAuthorities.deprecatedPkiRoutes` | deprecated /api/v1/pki routes are not exposed; this server uses the current /api/v1/cert-manager contract |
| `certificateAuthorities.der.read` | the pinned DER-serving route is intentionally public and does not authenticate a Machine Identity |
| `certificateAuthorities.external.admin` | external provider credentials remain closed while value-free metadata is available through certificateAuthorities.list |
| `certificateAuthorities.internal.autoRenewal` | CA auto-renewal configuration is not implemented in this build; explicit one-shot renewal is available |
| `certificateAuthorities.internal.installExternalCertificate` | queued Venafi and Azure AD CS certificate installation is outside the enabled provider set |
| `certificateAuthorities.internal.signingConfig` | external Venafi and Azure AD CS signing-provider configuration is outside the enabled provider set |
| `certificateSyncs.admin` | certificate synchronization providers are not implemented in this server |
| `certificateTemplates.admin` | general certificate-template administration is not implemented; typed certificate profiles own the supported enrollment workflows |
| `codeSigners.certificate.issue.external` | external certificate-authority provider families are not implemented in this build |
| `codeSigners.certificate.reissue.external` | external certificate-authority provider families are not implemented in this build |
| `dynamicSecretLeases.create.providersExceptSqlDatabase` | typed one-time lease credentials are currently implemented only for the sqlDatabase provider variant |
| `dynamicSecrets.create.providersExceptSqlDatabase` | typed creation is currently implemented only for the sqlDatabase provider variant |
| `dynamicSecrets.updateProviderInputs` | the pinned API exposes only a name-addressed replacement without an ID or version precondition, so a concurrent delete and recreation cannot be targeted safely |
| `events.subscriptions` | long-lived event subscriptions are outside the stateless MCP request contract |
| `externalMigrations.admin` | provider migration workflows are not implemented in this server |
| `groups.admin` | group creation, update, and deletion require Infisical&#x27;s Groups plan feature; partial administration is not exposed |
| `identities.search` | the server exposes bounded identity inventory and exact reads rather than the upstream search and count endpoints |
| `identityAliCloudAuth.admin` | Alibaba Cloud Auth is intentionally not implemented in this server |
| `identityAuth.tokenMinting` | provider login and access-token lifecycle routes are not MCP tools; callers authenticate to the gateway and the server owns its dedicated upstream token |
| `identityAwsAuth.admin` | AWS IAM Auth is intentionally not implemented in this server |
| `identityAzureAuth.admin` | Azure Auth is intentionally not implemented in this server |
| `identityGcpAuth.admin` | GCP Auth is intentionally not implemented in this server |
| `identityJwtAuth.admin` | JWT Auth is intentionally not implemented in this server |
| `identityKubernetesAuth.gateway.update` | Kubernetes token review through an Infisical Gateway requires a paid plan; existing gateway IDs remain visible as read-only metadata |
| `identityKubernetesAuth.gatewayPool.update` | Kubernetes token review through a Gateway Pool requires an Enterprise plan; existing pool IDs remain visible as read-only metadata |
| `identityKubernetesAuth.trustedIps.update` | trusted-IP mutation is an enterprise feature; current ranges remain visible as read-only metadata |
| `identityLdapAuth.admin` | LDAP Auth is intentionally not implemented in this server |
| `identityOciAuth.admin` | OCI Auth is intentionally not implemented in this server |
| `identityOidcAuth.admin` | OIDC Auth is intentionally not implemented in this server |
| `identitySpiffeAuth.admin` | SPIFFE Auth is intentionally not implemented in this server |
| `identityTlsCertificateAuth.admin` | TLS Certificate Auth is intentionally not implemented in this server |
| `identityTokenAuth.trustedIps.update` | trusted-IP mutation is an enterprise feature; current ranges remain visible as read-only metadata |
| `identityUniversalAuth.trustedIps.update` | trusted-IP mutation is an enterprise feature; current ranges remain visible as read-only metadata |
| `integrations.admin` | the pinned snapshot has no non-deprecated Machine-Identity-compatible integration administration contract |
| `kms.postQuantum.entitlementDetection` | post-quantum algorithms remain accepted as pinned typed variants, but Infisical enforces the kmsPqc plan entitlement and exposes no identity-token entitlement probe |
| `organizationGroupMemberships.admin` | organization group-membership administration is plan-gated and not exposed as a partial lifecycle |
| `organizationRoles.admin` | custom organization-role creation and update require Infisical&#x27;s RBAC plan feature; partial destructive administration is not exposed |
| `organizationScim.admin` | organization SCIM administration requires a user JWT and is not exposed through the Machine Identity |
| `organizationSso.admin` | organization SSO administration requires a user JWT and is not exposed through the Machine Identity |
| `organizations.admin` | the pinned organization administration routes require a user JWT and do not accept Universal Auth identity tokens |
| `organizations.read` | the pinned organization read routes require a user JWT and do not accept Universal Auth identity tokens |
| `pkiAlerts.admin` | certificate alert administration is not implemented in this server |
| `pkiCollections.admin` | legacy PKI collection administration is not implemented in this server |
| `pkiDiscovery.admin` | certificate discovery jobs and scans are not implemented in this server |
| `pkiInstallations.admin` | certificate installation targets are not implemented in this server |
| `projectGroupMemberships.admin` | project group-membership administration depends on the plan-gated group lifecycle and temporary role scheduling is not implemented |
| `projectMemberships.temporaryRoles.update` | temporary role creation and scheduling are not implemented; confirmed complete replacement may remove omitted temporary assignments |
| `projectRoles.admin` | custom project-role creation and update require Infisical&#x27;s RBAC plan feature; partial destructive administration is not exposed |
| `projectTemplates.admin` | project-template administration is not implemented in this server |
| `secretImports.replicationResync` | the pinned replication-resync route does not accept Universal Auth identity tokens |
| `secretImports.values.read` | bulk imported-secret values are intentionally omitted; reveal one exact secret with secrets.reveal |
| `secretRotations.otherProviders.lifecycle` | provider-tagged lifecycle operations are implemented only for PostgreSQL, MySQL, Microsoft SQL Server, and Oracle Database credential rotations; all other pinned providers, including AWS IAM, remain unavailable |
| `secretScanning.admin` | secret-scanning configuration, sources, scans, and findings are not implemented in this server |
| `secretSyncs.github.import` | the pinned GitHub destination declares canImportSecrets false |
| `secretSyncs.otherDestinations.admin` | provider-tagged administration is currently implemented only for the pinned GitHub destination contract |
| `secretSyncs.otherDestinations.run` | manual jobs for other destination-tagged contracts are not implemented |
| `secretVersions.read` | the pinned secret-version route does not accept Universal Auth identity tokens |
| `secrets.duplicate` | bulk secret duplication is intentionally omitted; writes require exact typed targets |
| `secrets.rollback` | supported point-in-time recovery routes require a user JWT; the older Universal Auth snapshot route is deprecated and always rejects requests |
| `serviceTokens.read` | legacy service tokens are superseded by Machine Identities and typed authentication methods |
| `sharedSecrets.admin` | anonymous shared-secret links are outside the exact authenticated reveal boundary |
| `sshHosts.globalInventory.read` | the pinned global inventory route requires JWT and cannot be served through Universal Auth |
| `sshHosts.userCertificate.issue` | the pinned route requires JWT and cannot be served through Universal Auth |
| `subOrganizations.admin` | sub-organization administration is not implemented in this server |
| `userProjectAdditionalPrivileges.admin` | the pinned user additional-privilege routes require a user JWT and do not accept Universal Auth identity tokens |
| `userProjectAdditionalPrivileges.read` | the pinned user additional-privilege routes require a user JWT and do not accept Universal Auth identity tokens |
| `users.read` | current-user and user-organization routes require a user JWT and do not accept the dedicated Machine Identity |
| `webhooks.admin` | the pinned snapshot has no non-deprecated Machine-Identity-compatible webhook administration contract |

## Checked identifier handoffs

These declared links are checked against the exported operation names and
input/output schema fields. They prove field presence and string types, not
caller authority, complete lifecycle coverage, or permission to change scope.

| Task | Source field | Consumer field | Scope to preserve |
| --- | --- | --- | --- |
| Project to environment inventory | `projects.list`: `items.[].id` | `environments.list`: `projectId` | Keep the selected project&#x27;s identifier. |
| Environment to secret metadata | `environments.list`: `environments.items.[].slug` | `secrets.metadata.list`: `environment` | When environments is present, keep the same project and select an exact folder path. |
| Secret metadata to exact reveal | `secrets.metadata.list`: `items.[].name` | `secrets.reveal`: `target.name` | Keep the same project, environment, and normalized folder path. |
| KMS inventory to exact key | `kms.keys.list`: `items.[].id` | `kms.keys.get`: `keyId` | Keep the same owning project. |
| Certificate inventory to exact certificate | `certificates.list`: `items.[].id` | `certificates.get`: `certificateId` | Keep the same Certificate Manager project. |
