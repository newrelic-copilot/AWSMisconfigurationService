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

# MISCONFIGURATION 1: Security group with overly permissive rules
resource "aws_security_group" "misconfigured_sg" {
  name_prefix = "misconfigured-sg-"
  vpc_id      = data.aws_vpc.default.id

  # Allow SSH from anywhere
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

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

  # Allow RDP from anywhere
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all database ports from anywhere
  ingress {
    description = "MySQL from anywhere"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL from anywhere"
    from_port   = 5432
    to_port     = 5432
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
    Name        = "MisconfiguredSecurityGroup"
    Environment = "SecurityTesting"
    Purpose     = "Intentionally vulnerable for testing"
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

  # MISCONFIGURATION: No key pair specified (but still accessible)
  # key_name = "your-key-pair"

  # MISCONFIGURATION: IMDSv1 enabled (should use IMDSv2 only)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # Should be "required" for IMDSv2
    http_put_response_hop_limit = 2
  }

  # MISCONFIGURATION: User data with sensitive information
  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    
    # SECURITY ISSUE: Hardcoded credentials in user data
    export DB_PASSWORD="SuperSecretPassword123!"
    export API_KEY="AKIA1234567890ABCDEF"
    
    # Create a simple web page
    echo "<h1>Misconfigured Web Server</h1>" > /var/www/html/index.html
    echo "<p>This server is intentionally misconfigured for security testing.</p>" >> /var/www/html/index.html
    echo "<p>Database Password: $DB_PASSWORD</p>" >> /var/www/html/index.html
    
    # SECURITY ISSUE: Disable firewall
    systemctl stop firewalld
    systemctl disable firewalld
    
    # SECURITY ISSUE: Create user with weak password
    useradd -m testuser
    echo "testuser:password123" | chpasswd
  EOF
  )

  # MISCONFIGURATION: Unencrypted root volume
  root_block_device {
    volume_type           = "gp2"
    volume_size           = 8
    encrypted             = false # Should be true
    delete_on_termination = true
  }

  # MISCONFIGURATION: No monitoring enabled
  monitoring = false

  tags = {
    Name        = "MisconfiguredEC2Instance"
    Environment = "SecurityTesting"
    Purpose     = "Intentionally vulnerable for testing"
  }
}

# MISCONFIGURATION 3: IAM role with overly broad permissions
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
    Name        = "MisconfiguredRole"
    Environment = "SecurityTesting"
    Purpose     = "Intentionally vulnerable for testing"
  }
}

# MISCONFIGURATION: Attach overly permissive policy
# REMEDIATION: Removed iam:* and replaced with least-privilege IAM actions.
# Broad iam:* permissions (especially iam:CreateAccessKey, iam:UpdateAccessKey,
# iam:ListAccessKeys) enable persistence tactics by allowing attackers to create
# and manage long-lived credentials. Only read-only IAM actions needed by EC2
# are retained.
resource "aws_iam_role_policy" "misconfigured_policy" {
  name = "MisconfiguredPolicy"
  role = aws_iam_role.misconfigured_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "rds:*"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetAccessKeyLastUsed"
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

output "security_warnings" {
  value = "WARNING: This EC2 instance is intentionally misconfigured with public access, weak security groups, unencrypted storage, and hardcoded credentials!"
}