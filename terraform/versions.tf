# versions.tf — provider + version pins.
# Pinned versions keep `terraform apply` reproducible across machines and over time,
# and let Checkov/tfsec reason about a known provider schema.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource in this lab is tagged so a stray leftover after a missed
  # `terraform destroy` is trivially findable in the console / Cost Explorer.
  default_tags {
    tags = {
      Project     = var.project
      Environment = "lab"
      ManagedBy   = "terraform"
      Warning     = "intentionally-vulnerable-do-not-deploy-to-prod"
    }
  }
}
