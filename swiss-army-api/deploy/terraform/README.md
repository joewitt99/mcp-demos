# swiss-army-api — Terraform deploy

Runs **one shared swiss-army-api instance** on AWS ECS Fargate from a pushed
image. Same module shape as `swiss-army-mcp/deploy/terraform`, minus ALB
stickiness (the API is stateless). Customers self-onboard at
`https://<your-host>/config`.

## What this creates

- CloudWatch log group, IAM exec + task roles (task role granted
  `ssm:GetParameter`, `PutParameter`, and `GetParametersByPath` on the tenants
  prefix)
- ALB + target group (`/healthz` health check) + HTTPS listener + host-header rule
- ECS cluster, task definition (image pinned to a tag), service
- Route 53 A-ALIAS record
- Optionally, a minimal demo VPC (`create_vpc = true`) — see `vpc.tf`

**Per-tenant SSM parameters are NOT managed by Terraform** — the app creates
them when customers self-onboard at `/config`. `terraform destroy` leaves them
in place. Clean those up with:

```
aws ssm get-parameters-by-path --path /swiss-army-api/tenants/ --query 'Parameters[].Name' --output text |
  xargs -n1 aws ssm delete-parameter --name
```

Bring your own: ACM cert (same region) and Route 53 hosted zone.

## Prerequisite: push the image

Fargate pulls at task start, so the tag must exist first (a missing tag fails
quietly — the task never passes `/healthz` and `terraform apply` still
succeeds). From `swiss-army-api/`:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t joewitt99/swiss-army-api:1.0.0 --push .
```

## Apply

```bash
cd mcp-demos/swiss-army-api/deploy/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # hostname, cert, zone, VPC
terraform init
terraform apply
```

It can share the VPC, subnets, hosted zone and a wildcard cert with a
swiss-army-mcp stack in the same account; `name` and `hostname` must differ
(defaults already do: `swiss-army-api`), and so should `tenants_prefix` — the
API's tenant record has a different shape from the MCP server's. It has its
own state directory, so no workspace juggling is needed.

Outputs include `config_url` (send customers here), `redirect_uri` (they add
it to their admin Okta SPA), and `openapi_url` (import into the Bridge).

## Customer onboarding (once the stack is up)

Each customer visits `https://<your-host>/config`:

1. Enter their Okta domain (e.g. `your-tenant.oktapreview.com`).
2. Enter their admin SPA `client_id`, after adding the displayed redirect URI
   to that SPA.
3. Log in (PKCE against their org auth server).
4. Fill in their custom authorization server (issuer, audience, workload
   client IDs) and optionally enable scope enforcement.

Changes take effect on the next API call — no redeploy.

## Upgrading the image

Bump `image_tag` and re-apply. ECS rolls a new task definition revision.
Tenants are reloaded from SSM at startup.

## Tear down

```bash
terraform destroy
```

## Notes

- **State**: local. Configure an S3 backend for team/CI use.
- **Single task**: tenant configs are cached in memory and refreshed only on
  startup and on `/config` saves, so keep `desired_count = 1` (as set).
- **Cost**: one ALB (~$16/mo) plus a single 0.25 vCPU Fargate task. No
  per-customer infrastructure.
