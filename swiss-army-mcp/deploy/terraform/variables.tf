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

variable "vpc_id" {
  description = "Existing VPC for ALB + tasks."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets (2+ AZs) for the ALB."
  type        = list(string)
}

variable "task_subnet_ids" {
  description = "Subnets where Fargate tasks run. Use private+NAT for prod, or the public subnets with assign_public_ip=true."
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Whether tasks get a public IP. Set true only when task_subnet_ids are public subnets without NAT."
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
