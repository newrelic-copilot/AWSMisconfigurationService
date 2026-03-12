# Secure S3 configuration for the customer invoices bucket
# Addresses CRITICAL security issue: S3 public write access (srx-demo-customer-invoices-222634381402-us-east-2)

variable "customer_invoices_writer_role_arn" {
  description = "ARN of the IAM role that is allowed to write objects to the customer invoices bucket"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::\\d{12}:role/.+", var.customer_invoices_writer_role_arn))
    error_message = "customer_invoices_writer_role_arn must be a valid IAM role ARN in the format arn:aws:iam::<account-id>:role/<role-name>."
  }
}

locals {
  customer_invoices_bucket_name = "srx-demo-customer-invoices-222634381402-us-east-2"
}

# Block all public access to the customer invoices bucket
resource "aws_s3_bucket_public_access_block" "customer_invoices" {
  bucket = local.customer_invoices_bucket_name

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Restrict write access to specific IAM role only
resource "aws_s3_bucket_policy" "customer_invoices" {
  bucket = local.customer_invoices_bucket_name

  depends_on = [aws_s3_bucket_public_access_block.customer_invoices]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedWriteAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.customer_invoices_writer_role_arn
        }
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${local.customer_invoices_bucket_name}/*"
      },
      {
        Sid    = "DenyPublicWrite"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${local.customer_invoices_bucket_name}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = var.customer_invoices_writer_role_arn
          }
        }
      }
    ]
  })
}
