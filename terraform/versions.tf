# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Jeff Mbita. https://github.com/Mbitajeff/claude-code-governance-kit

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}
