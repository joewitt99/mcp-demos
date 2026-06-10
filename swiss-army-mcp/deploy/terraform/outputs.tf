output "mcp_url" {
  description = "MCP endpoint customers point clients at."
  value       = "https://${var.hostname}/mcp"
}

output "config_url" {
  description = "Self-service tenant setup page."
  value       = "https://${var.hostname}/config"
}

output "redirect_uri" {
  description = "Customers add this as a redirect URI on their admin Okta SPA."
  value       = "https://${var.hostname}/config/callback"
}

output "tenants_prefix" {
  description = "SSM prefix under which per-tenant configs live."
  value       = var.tenants_prefix
}

output "ecs_service" {
  description = "ECS service identifier."
  value       = "${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
}

output "log_group" {
  description = "CloudWatch log group for the task."
  value       = aws_cloudwatch_log_group.this.name
}
