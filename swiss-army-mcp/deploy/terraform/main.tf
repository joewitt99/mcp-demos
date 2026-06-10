data "aws_caller_identity" "current" {}

locals {
  name              = "swiss-army-mcp"
  container_port    = 8000
  mcp_base_url      = "https://${var.hostname}"
  tenants_prefix    = var.tenants_prefix
  ssm_path_no_slash = trimsuffix(local.tenants_prefix, "/")
  # ARN for resources under the prefix (used by Get/Put per-tenant).
  ssm_tenants_arn = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_path_no_slash}/*"
  # ARN for the path itself (used by GetParametersByPath at hydrate time).
  ssm_prefix_arn = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${local.ssm_path_no_slash}"

  # Effective network values — created VPC takes precedence over inputs.
  effective_vpc_id           = var.create_vpc ? aws_vpc.this[0].id : var.vpc_id
  effective_public_subnets   = var.create_vpc ? aws_subnet.public[*].id : var.public_subnet_ids
  effective_task_subnets     = var.create_vpc ? aws_subnet.public[*].id : var.task_subnet_ids
  effective_assign_public_ip = var.create_vpc ? true : var.assign_public_ip

  tags = {
    project = "swiss-army-mcp"
    managed = "terraform"
  }
}

# ---------------------------------------------------------------------------
# CloudWatch logs
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_ecs" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "exec" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "exec_managed" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "task_ssm" {
  name = "${local.name}-ssm-tenants"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ssm:GetParameter", "ssm:PutParameter"],
        Resource = local.ssm_tenants_arn
      },
      {
        Effect = "Allow",
        Action = ["ssm:GetParametersByPath"],
        # AWS evaluates the path with and without trailing slash depending on
        # how the caller normalized it; grant both forms.
        Resource = [
          local.ssm_prefix_arn,
          "${local.ssm_prefix_arn}/"
        ]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb-sg"
  description = "Ingress to ${local.name} ALB"
  vpc_id      = local.effective_vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_egress" {
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "task" {
  name        = "${local.name}-task-sg"
  description = "${local.name} Fargate tasks"
  vpc_id      = local.effective_vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  security_group_id            = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "task_egress" {
  security_group_id = aws_security_group.task.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------------------
# ALB + target group + listener + host-header rule
# ---------------------------------------------------------------------------
resource "aws_lb" "this" {
  name               = "${local.name}-alb"
  load_balancer_type = "application"
  internal           = false
  subnets            = local.effective_public_subnets
  security_groups    = [aws_security_group.alb.id]
  tags               = local.tags
}

resource "aws_lb_target_group" "this" {
  name        = "${local.name}-tg"
  port        = local.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.effective_vpc_id

  health_check {
    protocol            = "HTTP"
    path                = "/mcp"
    matcher             = "200-499"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  stickiness {
    type            = "lb_cookie"
    enabled         = true
    cookie_duration = 3600
  }

  tags = local.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.cert_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "unknown host"
      status_code  = "404"
    }
  }

  tags = local.tags
}

resource "aws_lb_listener_rule" "host" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  condition {
    host_header {
      values = [var.hostname]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ---------------------------------------------------------------------------
# ECS cluster + task def + service
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "this" {
  name = local.name
  tags = local.tags
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = local.tags

  container_definitions = jsonencode([{
    name      = local.name
    image     = "joewitt99/swiss-army-mcp:${var.image_tag}"
    essential = true
    portMappings = [{
      containerPort = local.container_port
      protocol      = "tcp"
    }]
    environment = [
      { name = "HOST", value = "0.0.0.0" },
      { name = "PORT", value = tostring(local.container_port) },
      { name = "MCP_BASE_URL", value = local.mcp_base_url },
      { name = "MCP_TENANTS_PREFIX", value = local.tenants_prefix },
      { name = "AWS_REGION", value = var.aws_region },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name                              = local.name
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.this.arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60

  network_configuration {
    subnets          = local.effective_task_subnets
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = local.effective_assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = local.name
    container_port   = local.container_port
  }

  depends_on = [aws_lb_listener_rule.host]
  tags       = local.tags
}

# ---------------------------------------------------------------------------
# Route 53
# ---------------------------------------------------------------------------
resource "aws_route53_record" "this" {
  zone_id = var.hosted_zone_id
  name    = var.hostname
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = false
  }
}
