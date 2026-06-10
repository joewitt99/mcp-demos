variable "aws_region" {
  description = "AWS region for every resource. Must match the ACM cert region."
  type        = string
}

variable "hostname" {
  description = "Public hostname this stack serves (e.g. swiss-army-mcp.bridge.oktaproserv.com)."
  type        = string
}

variable "cert_arn" {
  description = "ARN of an existing ACM cert covering var.hostname, in var.aws_region."
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for the parent domain."
  type        = string
}

variable "create_vpc" {
  description = "When true, Terraform provisions a minimal demo VPC (IGW + 2 public subnets) and ignores vpc_id/public_subnet_ids/task_subnet_ids. When false, those three are required."
  type        = bool
  default     = false
}

variable "new_vpc_cidr" {
  description = "CIDR block to use when create_vpc=true. Subnets are carved as /20s in the first two available AZs."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "AZs to use for the created subnets when create_vpc=true. Provide at least 2 (e.g. [\"us-east-1a\", \"us-east-1b\"]). If empty (default), Terraform calls DescribeAvailabilityZones to auto-pick — set this explicitly if your IAM role denies that call."
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "Existing VPC for ALB + tasks. Required when create_vpc=false."
  type        = string
  default     = null
}

variable "public_subnet_ids" {
  description = "Public subnets (2+ AZs) for the ALB. Required when create_vpc=false."
  type        = list(string)
  default     = []
}

variable "task_subnet_ids" {
  description = "Subnets where Fargate tasks run. Use private+NAT for prod, or the public subnets with assign_public_ip=true. Required when create_vpc=false."
  type        = list(string)
  default     = []
}

variable "assign_public_ip" {
  description = "Whether tasks get a public IP. Ignored when create_vpc=true (forced to true since the created VPC has no NAT). Set true for bring-your-own public subnets without NAT."
  type        = bool
  default     = false
}

variable "image_tag" {
  description = "Tag of the joewitt99/swiss-army-mcp image to deploy. Pin a version for stability."
  type        = string
  default     = "0.5.0"
}

variable "tenants_prefix" {
  description = "SSM Parameter Store path prefix for per-tenant config blobs. Must end with /."
  type        = string
  default     = "/swiss-army-mcp/tenants/"
}

variable "task_cpu" {
  description = "Fargate CPU units (256 = 0.25 vCPU)."
  type        = string
  default     = "256"
}

variable "task_memory" {
  description = "Fargate memory in MB."
  type        = string
  default     = "512"
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 14
}
