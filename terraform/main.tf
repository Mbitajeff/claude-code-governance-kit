data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Model IDs inside an inference profile ID, e.g. "anthropic.claude-haiku-4-5-20251001-v1:0".
  model_ids = [for id in var.allowed_inference_profile_ids : join(".", slice(split(".", id), 1, length(split(".", id))))]

  inference_profile_arns = [
    for id in var.allowed_inference_profile_ids : "arn:aws:bedrock:${var.region}:${local.account_id}:inference-profile/${id}"
  ]

  # Cross-region inference routes to the foundation model in any region of the profile.
  foundation_model_arns = [for id in local.model_ids : "arn:aws:bedrock:*::foundation-model/${id}"]
}

# ---------------------------------------------------------------------------
# Cost guardrails: a monthly budget plus a daily circuit breaker.
# ---------------------------------------------------------------------------

resource "aws_budgets_budget" "bedrock_monthly" {
  name         = "${var.name_prefix}-bedrock-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.alert_emails
  }
}

resource "aws_budgets_budget" "bedrock_daily" {
  name         = "${var.name_prefix}-bedrock-daily"
  budget_type  = "COST"
  limit_amount = tostring(var.daily_budget_usd)
  limit_unit   = "USD"
  time_unit    = "DAILY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.alert_emails
  }
}

# ---------------------------------------------------------------------------
# Least-privilege identity for AI agents: invoke approved models, nothing else.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "agent_trust" {
  statement {
    sid     = "TrustedPrincipalsOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.agent_trusted_principal_arns
    }
  }
}

resource "aws_iam_role" "agent" {
  name                 = "${var.name_prefix}-bedrock-invoke"
  description          = "AI coding agents: invoke approved Bedrock models only"
  assume_role_policy   = data.aws_iam_policy_document.agent_trust.json
  max_session_duration = var.max_session_hours * 3600
}

data "aws_iam_policy_document" "agent_invoke" {
  statement {
    sid = "InvokeApprovedModelsOnly"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = concat(local.inference_profile_arns, local.foundation_model_arns)
  }

  statement {
    sid    = "NoModelOrGuardrailAdministration"
    effect = "Deny"
    actions = [
      "bedrock:Create*",
      "bedrock:Delete*",
      "bedrock:Update*",
      "bedrock:Put*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "agent_invoke" {
  name   = "invoke-approved-models"
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent_invoke.json
}
