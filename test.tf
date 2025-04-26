terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

###############################################################################
#  Provider
###############################################################################

variable "region" {
  description = "AWS Region to deploy the demo resources"
  type        = string
  default     = "eu-central-1"          # adjust if you like
}

provider "aws" {
  region = var.region
}

###############################################################################
#  Demo resource — just an S3 bucket
###############################################################################

# Generates a short, human-readable suffix so the bucket name is globally unique
resource "random_pet" "suffix" {
  length = 2
}

resource "aws_s3_bucket" "demo" {
  bucket = "gh-actions-demo-${random_pet.suffix.id}"

  tags = {
    Purpose     = "Terraform-PR-Demo"
    Environment = "pr"
  }
}

output "bucket_name" {
  value       = aws_s3_bucket.demo.bucket
  description = "The name of the S3 bucket created by this config"
}
