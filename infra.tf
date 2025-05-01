###############################################################################
# Terraform Required Providers
###############################################################################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40" # 5.33+ supports managed EBS on Fargate
    }
  }
  required_version = ">= 1.6"
}

###############################################################################
# 1. Provider and Variables
###############################################################################
provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "tls_domain" {
  description = "Primary domain (or wildcard) to match an existing ACM certificate"
  type        = string
  default     = "anim-alert.org"
}

data "aws_acm_certificate" "selected" {
  domain      = var.tls_domain
  statuses    = ["ISSUED"]
  most_recent = true
  types       = ["AMAZON_ISSUED"]
}

###############################################################################
# 2. Networking – NEW VPC, Subnets, NAT
###############################################################################
# Availability Zones
data "aws_availability_zones" "available" {}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "animalert-vpc" }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "animalert-igw" }
}

# Public Subnets (for ALB & NAT)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 1) # 10.0.1.0/24, 10.0.2.0/24
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  tags = { Name = "animalert-public-${count.index}" }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway (one shared)
resource "aws_eip" "nat" { domain = "vpc" }

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "animalert-nat" }
}

# Private Subnets (for ECS tasks)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 11) # 10.0.11.0/24, 10.0.12.0/24
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = { Name = "animalert-private-${count.index}" }
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Locals with subnet IDs
locals {
  public_subnets  = aws_subnet.public[*].id
  private_subnets = aws_subnet.private[*].id
}

###############################################################################
# 3. S3 Buckets (Images, Logs, Backups)
###############################################################################
resource "aws_s3_bucket" "images"  { bucket = "animalert-images"  }
resource "aws_s3_bucket" "logs"    { bucket = "animalert-logs"    }
resource "aws_s3_bucket" "backups" { bucket = "animalert-backups" }

# Allow ALB to write access logs
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "logs_allow_alb" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSLoadBalancerLoggingPut",
        Effect    = "Allow",
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = [
          "arn:aws:s3:::${aws_s3_bucket.logs.bucket}/alb-access-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        ],
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid       = "AWSLoadBalancerLoggingGetAcl",
        Effect    = "Allow",
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" },
        Action    = "s3:GetBucketAcl",
        Resource  = "arn:aws:s3:::${aws_s3_bucket.logs.bucket}"
      }
    ]
  })
}

###############################################################################
# 4. ECR Repository
###############################################################################
resource "aws_ecr_repository" "web_app_repo" {
  name                 = "animalert-webapp"
  image_tag_mutability = "MUTABLE"
}

###############################################################################
# 5. Security Groups – ALB (443) & ECS (3000) & DB (5432)
###############################################################################
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS in"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security group for web-app ECS tasks
resource "aws_security_group" "ecs_service_sg" {
  name   = "ecs-service-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Allow traffic from ALB"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security group for Postgres ECS tasks
resource "aws_security_group" "db_sg" {
  name   = "db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Postgres from ECS web-app tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_service_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

###############################################################################
# 6. Application Load Balancer & HTTPS Listener
###############################################################################
resource "aws_lb" "app_lb" {
  name               = "my-app-lb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = local.public_subnets

  access_logs {
    bucket  = aws_s3_bucket.logs.bucket
    prefix  = "alb-access-logs"
    enabled = true
  }
}

resource "aws_lb_target_group" "app_tg" {
  name        = "my-app-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path     = "/"
    port     = "traffic-port"
    protocol = "HTTP"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.selected.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

###############################################################################
# 7. ECS Cluster
###############################################################################
resource "aws_ecs_cluster" "main" {
  name = "animalert-ecs-cluster"
}

###############################################################################
# 7b. Service Discovery (Cloud Map) for internal DNS
###############################################################################
resource "aws_service_discovery_private_dns_namespace" "animalert" {
  name = "animalert.local"
  vpc  = aws_vpc.main.id
}

resource "aws_service_discovery_service" "db" {
  name        = "db"
  dns_config {
    namespace_id  = aws_service_discovery_private_dns_namespace.animalert.id
    dns_records   { type = "A" ttl = 10 }
    routing_policy = "MULTIVALUE"
  }
}

###############################################################################
# 8. IAM Roles – Execution, Task, Infrastructure
###############################################################################
# --- a) Execution Role -------------------------------------------------------
data "aws_iam_policy_document" "ecs_task_execution_assume_role" {
  statement {
    actions   = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name               = "ecsTaskExecutionRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- b) Task Role ------------------------------------------------------------
data "aws_iam_policy_document" "ecs_task_role_assume_role" {
  statement {
    actions   = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_role" {
  name               = "ecsTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_role_assume_role.json
}

data "aws_iam_policy_document" "ecs_task_s3_policy_doc" {
  statement {
    sid       = "AllowS3Access"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.images.arn}/*",
      "${aws_s3_bucket.logs.arn}/*",
      "${aws_s3_bucket.backups.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "ecs_task_s3_policy" {
  name   = "ecsTaskS3Policy"
  policy = data.aws_iam_policy_document.ecs_task_s3_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_s3_policy_attachment" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_s3_policy.arn
}

# --- c) Infrastructure Role (managed EBS volumes) ---------------------------
data "aws_iam_policy_document" "ecs_infra_assume_role" {
  statement {
    actions   = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_infra_role" {
  name               = "ecsInfrastructureRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_infra_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_infra_volumes_attachment" {
  role       = aws_iam_role.ecs_infra_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForVolumes"
}

###############################################################################
# 9. CloudWatch Log Groups
###############################################################################
resource "aws_cloudwatch_log_group" "web_app_lg" {
  name              = "/ecs/web-app"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "db_lg" {
  name              = "/ecs/db"
  retention_in_days = 7
}

###############################################################################
# 10a. ECS Task Definition – WEB APP
###############################################################################
resource "aws_ecs_task_definition" "web_app_task" {
  family                   = "animalert-web-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "web-app"
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:latest"
      essential = true

      portMappings = [
        { containerPort = 3000, protocol = "tcp" }
      ]

      environment = [
        { name = "DB_HOST", value = "db.animalert.local" },
        { name = "DB_PORT", value = "5432" },
        { name = "DB_NAME", value = "my_app_db" },
        { name = "DB_USER", value = "myuser" },
        { name = "DB_PASSWORD", value = "super-secret" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.web_app_lg.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "webapp"
        }
      }
    }
  ])
}

###############################################################################
# 10b. ECS Task Definition – POSTGRES
###############################################################################
resource "aws_ecs_task_definition" "db_task" {
  family                   = "animalert-db-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  volume {
    name                = "db-volume"
    configure_at_launch = true
  }

  container_definitions = jsonencode([
    {
      name      = "database"
      image     = "postgres:14"
      essential = true

      environment = [
        { name = "POSTGRES_DB",       value = "my_app_db" },
        { name = "POSTGRES_USER",     value = "myuser" },
        { name = "POSTGRES_PASSWORD", value = "super-secret" }
      ]

      mountPoints = [
        { sourceVolume = "db-volume", containerPath = "/var/lib/postgresql/data" }
      ]

      portMappings = [
        { containerPort = 5432, protocol = "tcp" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.db_lg.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "db"
        }
      }
    }
  ])
}

###############################################################################
# 11a. ECS Service – WEB APP (Fargate)
###############################################################################
resource "aws_ecs_service" "web_app_service" {
  name             = "animalert-web-app-service"
  cluster          = aws_ecs_cluster.main.arn
  launch_type      = "FARGATE"
  desired_count    = 2
  platform_version = "1.4.0"

  task_definition = aws_ecs_task_definition.web_app_task.arn

  network_configuration {
    subnets          = local.private_subnets
    security_groups  = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "web-app"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.https]
}

###############################################################################
# 11b. ECS Service – DATABASE (Fargate + managed EBS)
###############################################################################
resource "aws_ecs_service" "db_service" {
  name             = "animalert-db-service"
  cluster          = aws_ecs_cluster.main.arn
  launch_type      = "FARGATE"
  desired_count    = 1
  platform_version = "1.4.0"

  task_definition = aws_ecs_task_definition.db_task.arn

  network_configuration {
    subnets          = local.private_subnets
    security_groups  = [aws_security_group.db_sg.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.db.arn
  }

  volume_configuration {
    name = "db-volume"

    managed_ebs_volume {
      role_arn         = aws_iam_role.ecs_infra_role.arn
      encrypted        = true
      volume_type      = "gp3"
      size_in_gb       = 20
      iops             = 3000
      throughput       = 125
      file_system_type = "ext4"
    }
  }
}

###############################################################################
# END OF FILE
###############################################################################
