# Gateway and deployment rollout

## Upstream manifest

The checked-in [gateway manifest](../gateway-manifest.yaml) is the source copied
into `docker-home` during rollout. It uses Streamable HTTP, a static service
bearer resolved from the gateway environment, and per-call isolation with the
safe per-principal scope:

```yaml
name: infisical
transport: http
url: http://infisical-mcp:8000/mcp
auth:
  bearer_env: MCP_GATEWAY_UPSTREAM_BEARER_INFISICAL
session:
  isolation: per_call
  scope: per_principal
```

The manifest explicitly classifies the complete published tool catalog. Risk is
either `low` or `high`; the gateway-reserved `medium` class is never used.

The five local discovery tools contact nothing and return build metadata,
capability descriptions, or schemas, so they are low risk and carry no personal
data. The four executors are high risk and marked for personal data.

That is coarser than it was. The gateway authorizes on the tool name, and an
executor carries every operation of its tier, so the gateway can no longer tell
`projects.list` from `secrets.reveal` — both arrive as `infisical.read`. Each
executor is therefore classified for the most sensitive thing it can reach,
which never under-classifies a request but does mean a principal permitted to
read at all is permitted to reveal. This changes no access here, because the
confinement rule below already restricts every Infisical tool to one group, and
it is the reason that rule remains load-bearing rather than a backstop.
Restoring per-operation classification requires the gateway to authorize on the
operation argument, which is tracked in the gateway repository.

Repository tests parse the manifest's exact loader shape, require one entry in
catalog order for every published MCP tool, reject unknown risk values, bind
`side_effects` to the MCP read-only annotation, and assert that no operation is
reachable through an executor classified below it. Adding a tool to the MCP
catalog therefore does not expose it through the gateway: its explicit manifest
entry and classification must pass review first. The manifest is never generated
in CI from unreviewed MCP annotations.

## Group confinement

Creating a local `infisical-admin` group only creates the label; it grants
nothing and gives nobody membership. Each authorized gateway API key must be
assigned that group. Interactive OAuth identities need the equivalent group
claim or SCIM-provisioned membership.

The Cedar policy needs both directions:

```cedar
permit (
  principal in Group::"infisical-admin",
  action == Action::"CallTool",
  resource is Tool
) when { resource.server == "infisical" };

forbid (
  principal,
  action == Action::"CallTool",
  resource is Tool
) when { resource.server == "infisical" }
unless { principal in Group::"infisical-admin" };
```

Repository-standard policy metadata must be added when this becomes a gateway
change. The confinement rule prevents the general authenticated-user baseline
from opening Infisical’s low-risk reads. Golden policy tests must cover an admin
member, a groupless principal, an unrelated group, and every risk class.

## Secret ownership and rotation

Use a dedicated Infisical path for the MCP stack and a shared gateway reference
for the service bearer. The exact path will follow the `docker-home` convention
selected during rollout. At minimum it stores:

- the MCP server’s Universal Auth client ID and client secret
- the current ingress bearer and, temporarily, the previous bearer
- the gateway’s reference to the current ingress bearer

Generate the ingress bearer with a platform CSPRNG. Never place it in compose,
Git, a command line, or logs. Rotation order is server accepts new and old,
gateway switches to new, verification succeeds, then old is removed.

## Compose topology

```text
mcp-gateway -- infisical_mcp_private --> infisical-mcp
                                                |
                                  infisical_api_private
                                                |
                                         infisical app
```

The gateway never joins `infisical_api_private`. The MCP server never joins the
Infisical backend network containing Postgres and Redis. The stack exposes port
8000 only to Docker networks and has no host mapping or Traefik labels.
The sidecar reads the gateway JWKS over `infisical_mcp_private` with
`INFISICAL_MCP_IDENTITY_ALLOW_PRIVATE_HTTP=true`; the validating resolver
requires every `mcp-gateway` DNS answer to remain RFC 1918 or IPv6 unique-local
and rejects the IPv6 instance-metadata endpoint before the connector can send
the request.

The runtime follows the established sidecar hardening pattern: numeric non-root
user, read-only filesystem, small `noexec,nosuid,nodev` tmpfs, all capabilities
dropped, `no-new-privileges`, PID and CPU/memory limits, graceful shutdown, and
a binary healthcheck.

Komodo registration is a separate first step. Deployment automation is enabled
only after the generated stack identifier has been read from Komodo and added to
the workflow.
