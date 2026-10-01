# swiss-army-mcp — Terraform deploy

Spin up **one shared swiss-army-mcp instance** on AWS ECS Fargate using the
public Docker Hub image (`joewitt99/swiss-army-mcp`). No build, no push.
Customers self-onboard at `https://<your-host>/config`.

## What this creates

- CloudWatch log group, IAM exec + task roles (task role granted
  `ssm:GetParameter`, `PutParameter`, `GetParametersByPath` on the tenants
  prefix)
- ALB + target group + HTTPS listener + host-header rule
- ECS cluster, task definition (image pinned to a version tag), service
- Route 53 A-ALIAS record

**Per-tenant SSM parameters are NOT managed by Terraform** — the app creates
them when customers self-onboard at `/config`. `terraform destroy` leaves the
SSM parameters in place. Clean those up with:

```
aws ssm get-parameters-by-path --path /swiss-army-mcp/tenants/ --query 'Parameters[].Name' --output text |
  xargs -n1 aws ssm delete-parameter --name
```

Bring your own: ACM cert (same region) and Route 53 hosted zone.

**VPC: bring your own or let Terraform create one.**

| Mode | Set in tfvars | Notes |
| --- | --- | --- |
| BYO VPC | `create_vpc = false` (default) + `vpc_id`, `public_subnet_ids`, `task_subnet_ids` | Use existing networking. Set `assign_public_ip = true` if task subnets are public and have no NAT. |
| Terraform creates | `create_vpc = true` (+ optional `new_vpc_cidr`) | Minimal demo VPC: 1 VPC, IGW, 2 public /20 subnets in different AZs, default route. Tasks run in the public subnets with public IPs (no NAT, no extra cost). The BYO vars are ignored. |

## Running a second instance in the same VPC

Every resource name is derived from `var.name` (default `swiss-army-mcp`), so a
second stack is a second tfvars + a second state file — no code changes.

```bash
cd mcp-demos/swiss-army-mcp/deploy/terraform
cp second-instance.tfvars.example xaa.tfvars
$EDITOR xaa.tfvars                      # set name, hostname, cert_arn; reuse vpc_id/subnets

terraform workspace new xaa
terraform apply -var-file=xaa.tfvars
```

`terraform workspace` keeps the two state files apart in one directory. To
switch back: `terraform workspace select default`, then apply with
`terraform.tfvars` as usual. (A separate clone of this directory works too, if
you prefer two independent local states.)

Each stack gets its own ALB, target group, ECS cluster/service, IAM roles,
security groups, log group and Route 53 record. They share only the VPC,
subnets, hosted zone, and — optionally — the ACM cert and the SSM tenants
prefix.

| Must differ between stacks | Can be shared |
| --- | --- |
| `name`, `hostname` | `aws_region`, `vpc_id`, `public_subnet_ids`, `task_subnet_ids`, `hosted_zone_id` |
| Route 53 record (follows `hostname`) | `cert_arn`, if the cert covers both names (e.g. a `*.bridge.oktaproserv.com` wildcard) |
| | `tenants_prefix` — share it so tenants onboard once for both; or set a distinct prefix per stack for isolated tenant configs |

`MCP_BASE_URL` (and therefore `MCP_ISSUER`, which defaults to it) is derived
from `hostname`, so each stack is its own ID-JAG issuer and audience with no
extra configuration.

Cost of the second stack: one more ALB (~$16/mo) plus one more Fargate task.
To avoid the extra ALB you would need to share the first stack's listener — add
a second host-header rule (distinct `priority`) and target group against it
instead of creating an `aws_lb`. That is a larger refactor than this module
currently supports.

## Running from EC2

Use an Amazon Linux EC2 with an **IAM instance profile** that has the
permissions Terraform needs. `AdministratorAccess` is fine for demos; tighten
for production.

```bash
sudo yum install -y git yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum install -y terraform
git clone https://github.com/<you>/mcp-demos.git
cd mcp-demos/swiss-army-mcp/deploy/terraform
cp customer.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
terraform init
terraform apply
```

Outputs include the MCP URL, the `/config` URL, and the redirect URI that
customers add to their admin Okta SPA.

## Tear down

```bash
terraform destroy
```

Removes the ALB, ECS service, IAM roles, security groups, Route 53 record,
and log group. Tenant configs in SSM are preserved (see above).

## Customer onboarding (once the stack is up)

Each customer visits `https://<your-host>/config` and self-onboards:

1. Enter their Okta domain (e.g. `your-tenant.oktapreview.com`).
2. Enter their admin SPA `client_id`.
3. Add the displayed redirect URI to that Okta SPA.
4. Click Login → completes PKCE against the org auth server.
5. Fill in the custom authorization server (issuer, audience, workload
   client IDs) and optionally enable scope enforcement.

The settings persist to SSM under `/swiss-army-mcp/tenants/<their-domain>`.

## Notes

- **State**: this module uses local state. For team/CI use, configure an
  S3 backend.
- **Image upgrades**: bump `image_tag` (e.g. `0.5.0`) and re-apply. ECS does a
  rolling deploy of the new task definition revision.
- **Cost**: ALB + a single Fargate task. No per-customer infrastructure.
