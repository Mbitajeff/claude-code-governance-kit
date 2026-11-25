# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Jeff Mbita. https://github.com/Mbitajeff/claude-code-governance-kit

variable "region" {
  description = "AWS region where agents call Amazon Bedrock"
  type        = string
  default     = "us-west-2"
}

variable "name_prefix" {
  description = "Prefix for every resource name"
  type        = string
  default     = "ai-agents"
}

variable "monthly_budget_usd" {
  description = "Monthly Amazon Bedrock budget. Alerts at 80% actual and 100% forecast."
  type        = number
  default     = 100
}

variable "daily_budget_usd" {
  description = "Daily circuit breaker. A runaway agent loop shows up here long before the monthly budget."
  type        = number
  default     = 10
}

variable "alert_emails" {
  description = "Email addresses that receive budget alerts"
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "Provide at least one alert email."
  }
}

variable "agent_trusted_principal_arns" {
  description = "IAM principals allowed to assume the agent role (for example a CI role or an SSO permission set role)"
  type        = list(string)

  validation {
    condition     = length(var.agent_trusted_principal_arns) > 0
    error_message = "Provide at least one trusted principal ARN."
  }
}

variable "allowed_inference_profile_ids" {
  description = "Bedrock cross-region inference profile IDs the agent may invoke"
  type        = list(string)
  default = [
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
  ]
}

variable "max_session_hours" {
  description = "Maximum session length for the agent role. Short sessions limit the blast radius of a leaked credential."
  type        = number
  default     = 1
}
