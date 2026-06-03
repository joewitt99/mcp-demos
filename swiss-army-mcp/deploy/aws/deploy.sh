#!/usr/bin/env bash
# One-shot, idempotent deploy of swiss-army-mcp to AWS ECS Fargate behind an ALB.
# Re-run any time to roll a new image; it always builds a fresh tag and forces
# a new ECS deployment. Skips any resource that already exists.
#
# Usage:
#   cp vars.env.example vars.env  &&  $EDITOR vars.env
#   ./deploy.sh
#
# Requirements: aws CLI v2 authenticated, docker running, jq.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$HERE/../.." && pwd)"

if [[ ! -f "$HERE/vars.env" ]]; then
  echo "Missing $HERE/vars.env — copy vars.env.example to vars.env and edit." >&2
  exit 1
fi
# shellcheck disable=SC1091
source "$HERE/vars.env"

: "${AWS_REGION:?}"; : "${SERVICE_NAME:?}"; : "${HOSTNAME:?}"
: "${CERT_ARN:?}";  : "${HOSTED_ZONE_ID:?}";  : "${VPC_ID:?}"
: "${PUBLIC_SUBNET_IDS:?}"; : "${TASK_SUBNET_IDS:?}"
: "${OKTA_ISSUER:?}"; : "${OKTA_AUDIENCE:?}"

log()  { printf '\n\033[1;36m>>>\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_HOST="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_URI="${ECR_HOST}/${SERVICE_NAME}"
LOG_GROUP="/ecs/${SERVICE_NAME}"
CLUSTER_NAME="${CLUSTER_NAME:-mcp-demos}"
ALB_NAME="${ALB_NAME:-${CLUSTER_NAME}-alb}"
TG_NAME="${SERVICE_NAME}-tg"
EXEC_ROLE_NAME="${SERVICE_NAME}-exec"
TASK_ROLE_NAME="${SERVICE_NAME}-task"
ALB_SG_NAME="${ALB_NAME}-sg"
TASK_SG_NAME="${SERVICE_NAME}-task-sg"
IMAGE_TAG="${IMAGE_TAG:-$(date -u +%Y%m%d%H%M%S)}"

# ----------------------------------------------------------------------------
# 1. ECR repository
# ----------------------------------------------------------------------------
log "ECR repository ${SERVICE_NAME}"
if ! aws ecr describe-repositories --repository-names "$SERVICE_NAME" \
       --region "$AWS_REGION" >/dev/null 2>&1; then
  aws ecr create-repository --repository-name "$SERVICE_NAME" \
    --image-scanning-configuration scanOnPush=true \
    --region "$AWS_REGION" >/dev/null
  note "created"
else
  note "exists"
fi

# ----------------------------------------------------------------------------
# 2. Build & push image (linux/amd64 — Fargate is x86_64 by default)
# ----------------------------------------------------------------------------
log "Building and pushing ${ECR_URI}:${IMAGE_TAG}"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_HOST" >/dev/null

docker build --platform=linux/amd64 \
  -t "${ECR_URI}:${IMAGE_TAG}" -t "${ECR_URI}:latest" "$PROJECT_DIR"
docker push "${ECR_URI}:${IMAGE_TAG}" >/dev/null
docker push "${ECR_URI}:latest"      >/dev/null

# ----------------------------------------------------------------------------
# 3. CloudWatch log group
# ----------------------------------------------------------------------------
log "Log group ${LOG_GROUP}"
if ! aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" \
       --region "$AWS_REGION" \
       --query "logGroups[?logGroupName=='${LOG_GROUP}']" --output text | grep -q .; then
  aws logs create-log-group --log-group-name "$LOG_GROUP" --region "$AWS_REGION"
  aws logs put-retention-policy --log-group-name "$LOG_GROUP" \
    --retention-in-days 14 --region "$AWS_REGION"
  note "created"
else
  note "exists"
fi

# ----------------------------------------------------------------------------
# 4. IAM roles
# ----------------------------------------------------------------------------
ASSUME='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

log "IAM execution role ${EXEC_ROLE_NAME}"
if ! aws iam get-role --role-name "$EXEC_ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$EXEC_ROLE_NAME" \
    --assume-role-policy-document "$ASSUME" >/dev/null
  aws iam attach-role-policy --role-name "$EXEC_ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
  note "created"
else
  note "exists"
fi
EXEC_ROLE_ARN=$(aws iam get-role --role-name "$EXEC_ROLE_NAME" --query Role.Arn --output text)

log "IAM task role ${TASK_ROLE_NAME}"
if ! aws iam get-role --role-name "$TASK_ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$TASK_ROLE_NAME" \
    --assume-role-policy-document "$ASSUME" >/dev/null
  note "created"
else
  note "exists"
fi
TASK_ROLE_ARN=$(aws iam get-role --role-name "$TASK_ROLE_NAME" --query Role.Arn --output text)

# ----------------------------------------------------------------------------
# 5. Security groups
# ----------------------------------------------------------------------------
sg_id() {
  aws ec2 describe-security-groups --region "$AWS_REGION" \
    --filters "Name=group-name,Values=$1" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null
}

log "ALB security group ${ALB_SG_NAME}"
ALB_SG_ID=$(sg_id "$ALB_SG_NAME")
if [[ "$ALB_SG_ID" == "None" || -z "$ALB_SG_ID" ]]; then
  ALB_SG_ID=$(aws ec2 create-security-group \
    --group-name "$ALB_SG_NAME" --description "$ALB_NAME ingress" \
    --vpc-id "$VPC_ID" --region "$AWS_REGION" \
    --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id "$ALB_SG_ID" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0 --region "$AWS_REGION" >/dev/null
  note "created $ALB_SG_ID"
else
  note "exists $ALB_SG_ID"
fi

log "Task security group ${TASK_SG_NAME}"
TASK_SG_ID=$(sg_id "$TASK_SG_NAME")
if [[ "$TASK_SG_ID" == "None" || -z "$TASK_SG_ID" ]]; then
  TASK_SG_ID=$(aws ec2 create-security-group \
    --group-name "$TASK_SG_NAME" --description "$SERVICE_NAME tasks" \
    --vpc-id "$VPC_ID" --region "$AWS_REGION" \
    --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id "$TASK_SG_ID" \
    --protocol tcp --port "$CONTAINER_PORT" \
    --source-group "$ALB_SG_ID" --region "$AWS_REGION" >/dev/null
  note "created $TASK_SG_ID"
else
  note "exists $TASK_SG_ID"
fi

# ----------------------------------------------------------------------------
# 6. ECS cluster
# ----------------------------------------------------------------------------
log "ECS cluster ${CLUSTER_NAME}"
if ! aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region "$AWS_REGION" \
       --query "clusters[?status=='ACTIVE']" --output text | grep -q .; then
  aws ecs create-cluster --cluster-name "$CLUSTER_NAME" --region "$AWS_REGION" >/dev/null
  note "created"
else
  note "exists"
fi

# ----------------------------------------------------------------------------
# 7. ALB
# ----------------------------------------------------------------------------
log "Application Load Balancer ${ALB_NAME}"
ALB_ARN=$(aws elbv2 describe-load-balancers --names "$ALB_NAME" --region "$AWS_REGION" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || true)
if [[ "$ALB_ARN" == "None" || -z "$ALB_ARN" ]]; then
  ALB_ARN=$(aws elbv2 create-load-balancer --name "$ALB_NAME" \
    --subnets ${PUBLIC_SUBNET_IDS//,/ } \
    --security-groups "$ALB_SG_ID" \
    --scheme internet-facing --type application --ip-address-type ipv4 \
    --region "$AWS_REGION" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)
  note "created"
else
  note "exists"
fi
ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
  --region "$AWS_REGION" --query 'LoadBalancers[0].DNSName' --output text)
ALB_ZONE_ID=$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
  --region "$AWS_REGION" --query 'LoadBalancers[0].CanonicalHostedZoneId' --output text)

# ----------------------------------------------------------------------------
# 8. Target group
# ----------------------------------------------------------------------------
log "Target group ${TG_NAME}"
TG_ARN=$(aws elbv2 describe-target-groups --names "$TG_NAME" --region "$AWS_REGION" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || true)
if [[ "$TG_ARN" == "None" || -z "$TG_ARN" ]]; then
  TG_ARN=$(aws elbv2 create-target-group --name "$TG_NAME" \
    --protocol HTTP --port "$CONTAINER_PORT" \
    --vpc-id "$VPC_ID" --target-type ip \
    --health-check-protocol HTTP --health-check-path "/mcp" \
    --health-check-interval-seconds 30 --health-check-timeout-seconds 5 \
    --healthy-threshold-count 2 --unhealthy-threshold-count 3 \
    --matcher 'HttpCode=200-499' \
    --region "$AWS_REGION" \
    --query 'TargetGroups[0].TargetGroupArn' --output text)
  # Enable session stickiness on the load-balancer cookie (helps if you ever
  # bump DESIRED_COUNT > 1, even though MCP doesn't use cookies natively).
  aws elbv2 modify-target-group-attributes --target-group-arn "$TG_ARN" \
    --attributes \
      Key=stickiness.enabled,Value=true \
      Key=stickiness.type,Value=lb_cookie \
      Key=stickiness.lb_cookie.duration_seconds,Value=3600 \
    --region "$AWS_REGION" >/dev/null
  note "created"
else
  note "exists"
fi

# ----------------------------------------------------------------------------
# 9. HTTPS listener (created with a fixed-404 default; rules forward by host)
# ----------------------------------------------------------------------------
log "HTTPS listener on ${ALB_NAME}"
LISTENER_ARN=$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" \
  --region "$AWS_REGION" \
  --query "Listeners[?Port==\`443\`].ListenerArn | [0]" --output text 2>/dev/null || true)
if [[ "$LISTENER_ARN" == "None" || -z "$LISTENER_ARN" ]]; then
  LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "$ALB_ARN" \
    --protocol HTTPS --port 443 \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
    --certificates "CertificateArn=$CERT_ARN" \
    --default-actions 'Type=fixed-response,FixedResponseConfig={StatusCode=404,ContentType=text/plain,MessageBody="unknown host"}' \
    --region "$AWS_REGION" \
    --query 'Listeners[0].ListenerArn' --output text)
  note "created"
else
  # Make sure our cert is attached (idempotent if already added).
  aws elbv2 add-listener-certificates --listener-arn "$LISTENER_ARN" \
    --certificates "CertificateArn=$CERT_ARN" --region "$AWS_REGION" >/dev/null 2>&1 || true
  note "exists"
fi

# ----------------------------------------------------------------------------
# 10. Host-header rule routing $HOSTNAME -> target group
# ----------------------------------------------------------------------------
log "Listener rule for host ${HOSTNAME}"
RULE_ARN=$(aws elbv2 describe-rules --listener-arn "$LISTENER_ARN" --region "$AWS_REGION" \
  --query "Rules[?Conditions[?Field=='host-header' && contains(Values, '${HOSTNAME}')]].RuleArn | [0]" \
  --output text 2>/dev/null || true)
if [[ "$RULE_ARN" == "None" || -z "$RULE_ARN" ]]; then
  USED_PRIOS=$(aws elbv2 describe-rules --listener-arn "$LISTENER_ARN" \
    --region "$AWS_REGION" \
    --query "Rules[?Priority!='default'].Priority" --output text | tr '\t' '\n' | sort -n)
  NEXT_PRIO=1
  for p in $USED_PRIOS; do [[ $p -ge $NEXT_PRIO ]] && NEXT_PRIO=$((p + 1)); done
  aws elbv2 create-rule --listener-arn "$LISTENER_ARN" \
    --priority "$NEXT_PRIO" \
    --conditions "Field=host-header,Values=$HOSTNAME" \
    --actions "Type=forward,TargetGroupArn=$TG_ARN" \
    --region "$AWS_REGION" >/dev/null
  note "created (priority $NEXT_PRIO)"
else
  note "exists"
fi

# ----------------------------------------------------------------------------
# 11. ECS task definition (always register a new revision)
# ----------------------------------------------------------------------------
log "ECS task definition ${SERVICE_NAME}"
TASKDEF_FILE="$(mktemp)"
cat >"$TASKDEF_FILE" <<JSON
{
  "family": "$SERVICE_NAME",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "$TASK_CPU",
  "memory": "$TASK_MEMORY",
  "executionRoleArn": "$EXEC_ROLE_ARN",
  "taskRoleArn": "$TASK_ROLE_ARN",
  "containerDefinitions": [{
    "name": "$SERVICE_NAME",
    "image": "${ECR_URI}:${IMAGE_TAG}",
    "essential": true,
    "portMappings": [{"containerPort": $CONTAINER_PORT, "protocol": "tcp"}],
    "environment": [
      {"name": "HOST", "value": "0.0.0.0"},
      {"name": "PORT", "value": "$CONTAINER_PORT"},
      {"name": "MCP_LIST_PAGE_SIZE", "value": "${MCP_LIST_PAGE_SIZE:-30}"},
      {"name": "OKTA_ISSUER", "value": "$OKTA_ISSUER"},
      {"name": "OKTA_AUDIENCE", "value": "$OKTA_AUDIENCE"},
      {"name": "OKTA_CLIENT_IDS", "value": "${OKTA_CLIENT_IDS:-}"},
      {"name": "OKTA_DOMAIN", "value": "${OKTA_DOMAIN:-}"},
      {"name": "OKTA_REQUIRED_SCOPES", "value": "${OKTA_REQUIRED_SCOPES:-}"},
      {"name": "MCP_BASE_URL", "value": "https://${HOSTNAME}"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "$LOG_GROUP",
        "awslogs-region": "$AWS_REGION",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }]
}
JSON
TASKDEF_ARN=$(aws ecs register-task-definition --cli-input-json "file://$TASKDEF_FILE" \
  --region "$AWS_REGION" --query 'taskDefinition.taskDefinitionArn' --output text)
note "registered $TASKDEF_ARN"

# ----------------------------------------------------------------------------
# 12. ECS service
# ----------------------------------------------------------------------------
log "ECS service ${SERVICE_NAME}"
NET_CFG="awsvpcConfiguration={subnets=[${TASK_SUBNET_IDS}],securityGroups=[${TASK_SG_ID}],assignPublicIp=${ASSIGN_PUBLIC_IP:-DISABLED}}"
if aws ecs describe-services --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" \
     --region "$AWS_REGION" --query "services[?status=='ACTIVE']" --output text | grep -q .; then
  aws ecs update-service --cluster "$CLUSTER_NAME" --service "$SERVICE_NAME" \
    --task-definition "$TASKDEF_ARN" --force-new-deployment \
    --network-configuration "$NET_CFG" \
    --region "$AWS_REGION" >/dev/null
  note "updated"
else
  aws ecs create-service --cluster "$CLUSTER_NAME" --service-name "$SERVICE_NAME" \
    --task-definition "$TASKDEF_ARN" --desired-count "${DESIRED_COUNT:-1}" \
    --launch-type FARGATE \
    --network-configuration "$NET_CFG" \
    --load-balancers "targetGroupArn=$TG_ARN,containerName=$SERVICE_NAME,containerPort=$CONTAINER_PORT" \
    --health-check-grace-period-seconds 60 \
    --region "$AWS_REGION" >/dev/null
  note "created"
fi

# ----------------------------------------------------------------------------
# 13. Route 53 A-ALIAS record -> ALB
# ----------------------------------------------------------------------------
log "Route 53 ${HOSTNAME} -> ${ALB_DNS}"
CHANGE_FILE="$(mktemp)"
cat >"$CHANGE_FILE" <<JSON
{"Changes":[{
  "Action":"UPSERT",
  "ResourceRecordSet":{
    "Name":"$HOSTNAME","Type":"A",
    "AliasTarget":{"HostedZoneId":"$ALB_ZONE_ID","DNSName":"$ALB_DNS","EvaluateTargetHealth":false}
  }
}]}
JSON
aws route53 change-resource-record-sets \
  --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch "file://$CHANGE_FILE" >/dev/null
note "upserted"

cat <<DONE

\033[1;32m✓ Deploy complete\033[0m
  Endpoint:  https://${HOSTNAME}/mcp
  Image:     ${ECR_URI}:${IMAGE_TAG}
  Cluster:   ${CLUSTER_NAME}
  Task def:  ${TASKDEF_ARN##*/}

Next:
  Stream logs:   aws logs tail ${LOG_GROUP} --follow --region ${AWS_REGION}
  Service info:  aws ecs describe-services --cluster ${CLUSTER_NAME} --services ${SERVICE_NAME} --region ${AWS_REGION}
  Smoke test:    curl -sI https://${HOSTNAME}/mcp        (expect 401 — auth required)
DONE
