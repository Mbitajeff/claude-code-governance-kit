# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Jeff Mbita. https://github.com/Mbitajeff/claude-code-governance-kit

output "agent_role_arn" {
  description = "Role for AI agents to assume. It can only invoke the approved Bedrock models."
  value       = aws_iam_role.agent.arn
}

output "monthly_budget_name" {
  value = aws_budgets_budget.bedrock_monthly.name
}

output "daily_budget_name" {
  value = aws_budgets_budget.bedrock_daily.name
}
