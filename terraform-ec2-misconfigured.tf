# Intentionally Misconfigured EC2 Instance - FOR SECURITY TESTING ONLY
# This file contains multiple security misconfigurations and should NOT be used in production

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get default subnet
data "aws_subnet" "default" {
  vpc_id            = data.aws_vpc.default.id
  availability_zone = "us-east-1a"
  default_for_az    = true
}

# Security group with least-privilege network access
resource "aws_security_group" "misconfigured_sg" {
  name_prefix = "misconfigured-sg-"
  vpc_id      = data.aws_vpc.default.id

  # Allow HTTP from anywhere
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS from anywhere
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name             = "MisconfiguredSecurityGroup"
    Environment      = "SecurityTesting"
    Purpose          = "Intentionally vulnerable for testing"
    SecurityRisk     = "high"
    MonitoringTarget = "true"
  }
}

# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# MISCONFIGURATION 2: EC2 instance with multiple security issues
resource "aws_instance" "misconfigured_ec2" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"

  # MISCONFIGURATION: Use default subnet (public)
  subnet_id = data.aws_subnet.default.id

  # MISCONFIGURATION: Associate public IP
  associate_public_ip_address = true

  # MISCONFIGURATION: Use overly permissive security group
  vpc_security_group_ids = [aws_security_group.misconfigured_sg.id]

  # Attach IAM instance profile
  iam_instance_profile = aws_iam_instance_profile.misconfigured_profile.name

  # IMDSv2 enforced to prevent SSRF-based credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd

    # Create a simple web page
    echo "<h1>Web Server</h1>" > /var/www/html/index.html
    echo "<p>This server is configured for security testing.</p>" >> /var/www/html/index.html
  EOF
  )

  # Encrypted root volume
  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  # Detailed monitoring enabled
  monitoring = true

  tags = {
    Name             = "MisconfiguredEC2Instance"
    Environment      = "SecurityTesting"
    Purpose          = "Intentionally vulnerable for testing"
    SecurityRisk     = "high"
    MonitoringTarget = "true"
  }
}

# MISCONFIGURATION 3: IAM role — hardened to least-privilege trust policy
resource "aws_iam_role" "misconfigured_role" {
  name = "MisconfiguredEC2Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name             = "MisconfiguredRole"
    Environment      = "SecurityTesting"
    Purpose          = "Intentionally vulnerable for testing"
    SecurityRisk     = "high"
    MonitoringTarget = "true"
  }
}

# Least-privilege policy: only CloudWatch Logs permissions required for the workload
resource "aws_iam_role_policy" "misconfigured_policy" {
  name = "MisconfiguredPolicy"
  role = aws_iam_role.misconfigured_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
    ]
  })
}

# Instance profile for the role
resource "aws_iam_instance_profile" "misconfigured_profile" {
  name = "MisconfiguredProfile"
  role = aws_iam_role.misconfigured_role.name

  tags = {
    Name             = "MisconfiguredProfile"
    Environment      = "SecurityTesting"
    Purpose          = "Intentionally vulnerable for testing"
    SecurityRisk     = "high"
    MonitoringTarget = "true"
  }
}

# Launch template referencing the secured IAM instance profile
resource "aws_launch_template" "secure_lt" {
  name_prefix   = "secure-lt-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"

  iam_instance_profile {
    name = aws_iam_instance_profile.misconfigured_profile.name
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = true
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.misconfigured_sg.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp2"
      volume_size           = 8
      encrypted             = true
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name             = "SecureLaunchTemplateInstance"
      Environment      = "SecurityTesting"
      Purpose          = "Intentionally vulnerable for testing"
      SecurityRisk     = "high"
      MonitoringTarget = "true"
    }
  }

  tags = {
    Name             = "SecureLaunchTemplate"
    Environment      = "SecurityTesting"
    Purpose          = "Intentionally vulnerable for testing"
    SecurityRisk     = "high"
    MonitoringTarget = "true"
  }
}

# Output important information
output "instance_id" {
  value = aws_instance.misconfigured_ec2.id
}

output "public_ip" {
  value = aws_instance.misconfigured_ec2.public_ip
}

output "public_dns" {
  value = aws_instance.misconfigured_ec2.public_dns
}

output "security_group_id" {
  value = aws_security_group.misconfigured_sg.id
}

output "launch_template_id" {
  value = aws_launch_template.secure_lt.id
}

output "iam_role_arn" {
  value = aws_iam_role.misconfigured_role.arn
}

output "security_warnings" {
  value = "WARNING: This EC2 instance is intentionally misconfigured with public access. IAM role, instance profile, launch template, security groups, encryption, and monitoring have been hardened per security remediation guidance."
}