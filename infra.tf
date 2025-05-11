###############################################################################
# Terraform – provider requirements
###############################################################################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
  required_version = ">= 1.6"
}

###############################################################################
# 1. Provider & variables
###############################################################################
provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "tls_domain" {
  type    = string
  default = "anim-alert.org"
}

variable "db_name" {
  type = string
}

variable "db_user" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "google_api_id" {
  type      = string
  sensitive = true
}

variable "google_api_key" {
  type      = string
  sensitive = true
}

variable "site_origin" {
  type    = string
  default = "https://anim-alert.org"
}

variable "local_origin" {
  type    = string
  default = "http://localhost:3000"
}

# --------------------------------
# NEW VARIABLES FOR STAGING
# --------------------------------
variable "db_name_stage" {
  type    = string
  default = "animalert_stage"
}

variable "stage_subdomain" {
  type    = string
  default = "stage.anim-alert.org"
}

###############################################################################
# 2. ACM certificate
###############################################################################
data "aws_acm_certificate" "selected" {
  domain      = var.tls_domain
  statuses    = ["ISSUED"]
  most_recent = true
  types       = ["AMAZON_ISSUED"]
}

###############################################################################
# 3. Networking – VPC, subnets, NAT
###############################################################################
data "aws_availability_zones" "available" {}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "animalert-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "animalert-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 1)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "animalert-public-${count.index}"
  }
}

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

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "animalert-nat"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 11)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "animalert-private-${count.index}"
  }
}

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

locals {
  public_subnets  = aws_subnet.public[*].id
  private_subnets = aws_subnet.private[*].id
}

###############################################################################
# 4. S3 buckets (images, logs, backups)
###############################################################################
resource "aws_s3_bucket" "images" {
  bucket = "animalert-images"
}

resource "aws_s3_bucket" "logs" {
  bucket = "animalert-logs"
}

resource "aws_s3_bucket" "backups" {
  bucket = "animalert-backups"
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "logs_allow_alb" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSLoadBalancerLoggingPut",
        Effect    = "Allow",
        Principal = { Service = "logdelivery.elasticloadbalancing.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "arn:aws:s3:::${aws_s3_bucket.logs.bucket}/alb-access-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
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

resource "aws_s3_bucket_cors_configuration" "cors" {
  bucket = aws_s3_bucket.images.id

  cors_rule {
    id              = "web-and-local"
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = [
      var.site_origin,
      var.local_origin
    ]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

###############################################################################
# 5. ECR repository
###############################################################################
resource "aws_ecr_repository" "web_app_repo" {
  name                 = "animalert-webapp"
  image_tag_mutability = "MUTABLE"
}

###############################################################################
# 6. Security groups
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

resource "aws_security_group" "ecs_service_sg" {
  name   = "ecs-service-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "HTTP from ALB"
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

resource "aws_security_group" "db_sg" {
  name   = "db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Postgres from ECS tasks"
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
# 7. Application Load Balancer
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

# -----------------------------
# MAIN (production) target group
# -----------------------------
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

# -----------------------------
# STAGING target group
# -----------------------------
resource "aws_lb_target_group" "app_tg_stage" {
  name        = "my-app-stage-tg"
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

# Listener rule to match the staging subdomain
resource "aws_lb_listener_rule" "stage" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg_stage.arn
  }

  condition {
    host_header {
      values = [var.stage_subdomain]
    }
  }
}

###############################################################################
# 8. ECS cluster
###############################################################################
resource "aws_ecs_cluster" "main" {
  name = "animalert-ecs-cluster"
}

###############################################################################
# 9. IAM roles (execution / task)
###############################################################################
data "aws_iam_policy_document" "ecs_task_execution_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

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

data "aws_iam_policy_document" "ecs_task_role_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

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
    sid     = "AllowS3Access"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
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

###############################################################################
# 10. CloudWatch log group
###############################################################################
resource "aws_cloudwatch_log_group" "web_app_lg" {
  name              = "/ecs/web-app"
  retention_in_days = 7
}

###############################################################################
# 11. ECS task definitions – web app
###############################################################################
# Production
resource "aws_ecs_task_definition" "web_app_task" {
  family                   = "animalert-web-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "web-app",
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:latest",
      essential = true,

      portMappings = [
        {
          containerPort = 3000,
          protocol      = "tcp"
        }
      ],

      environment = [
        {
          name  = "DB_HOST",
          value = aws_db_instance.postgres.endpoint
        },
        {
          name  = "DB_PORT",
          value = tostring(aws_db_instance.postgres.port)
        },
        {
          name  = "DB_NAME",
          value = var.db_name
        },
        {
          name  = "DB_USER",
          value = var.db_user
        },
        {
          name  = "DB_PASSWORD",
          value = var.db_password
        },
        {
          name  = "NEXT_PUBLIC_GOOGLE_MAPS_MAP_ID",
          value = var.google_api_id
        },
        {
          name  = "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY",
          value = var.google_api_key
        },
        {
          name  = "AWS_S3_BUCKET_NAME",
          value = "animalert-images"
        },
        {
          name  = "DATABASE_URL",
          value = format(
            "postgresql://%s:%s@%s:%s/%s?sslmode=require",
            var.db_user,
            var.db_password,
            aws_db_instance.postgres.address,
            tostring(aws_db_instance.postgres.port),
            var.db_name
          )
        }
      ],

      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.web_app_lg.name,
          awslogs-region        = var.aws_region,
          awslogs-stream-prefix = "webapp"
        }
      }
    }
  ])
}

# Staging
resource "aws_ecs_task_definition" "web_app_task_stage" {
  family                   = "animalert-web-app-task-stage"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "web-app-stage",
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:latest",
      essential = true,

      portMappings = [
        {
          containerPort = 3000,
          protocol      = "tcp"
        }
      ],

      environment = [
        {
          name  = "DB_HOST",
          value = aws_db_instance.postgres.endpoint
        },
        {
          name  = "DB_PORT",
          value = tostring(aws_db_instance.postgres.port)
        },
        {
          name  = "DB_NAME",
          value = var.db_name_stage
        },
        {
          name  = "DB_USER",
          value = var.db_user
        },
        {
          name  = "DB_PASSWORD",
          value = var.db_password
        },
        {
          name  = "NEXT_PUBLIC_GOOGLE_MAPS_MAP_ID",
          value = var.google_api_id
        },
        {
          name  = "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY",
          value = var.google_api_key
        },
        {
          name  = "AWS_S3_BUCKET_NAME",
          value = "animalert-images"
        },
        {
          name  = "DATABASE_URL",
          value = format(
            "postgresql://%s:%s@%s:%s/%s?sslmode=require",
            var.db_user,
            var.db_password,
            aws_db_instance.postgres.address,
            tostring(aws_db_instance.postgres.port),
            var.db_name_stage
          )
        }
      ],

      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.web_app_lg.name,
          awslogs-region        = var.aws_region,
          awslogs-stream-prefix = "webapp-stage"
        }
      }
    }
  ])
}

###############################################################################
# 12. ECS services – web app
###############################################################################
# Production service
resource "aws_ecs_service" "web_app_service" {
  name             = "animalert-web-app-service"
  cluster          = aws_ecs_cluster.main.arn
  launch_type      = "FARGATE"
  desired_count    = 1
  platform_version = "1.4.0"
  task_definition  = aws_ecs_task_definition.web_app_task.arn

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

  depends_on = [
    aws_lb_listener.https
  ]
}

# Staging service
resource "aws_ecs_service" "web_app_service_stage" {
  name             = "animalert-web-app-service-stage"
  cluster          = aws_ecs_cluster.main.arn
  launch_type      = "FARGATE"
  desired_count    = 1
  platform_version = "1.4.0"
  task_definition  = aws_ecs_task_definition.web_app_task_stage.arn

  network_configuration {
    subnets          = local.private_subnets
    security_groups  = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg_stage.arn
    container_name   = "web-app-stage"
    container_port   = 3000
  }

  depends_on = [
    aws_lb_listener_rule.stage
  ]
}

###############################################################################
# 13. RDS PostgreSQL (db.t4g.micro)
###############################################################################
resource "aws_db_subnet_group" "postgres" {
  name       = "animalert-db-subnet-group"
  subnet_ids = local.private_subnets

  tags = {
    Name = "animalert-db-subnet-group"
  }
}

resource "aws_db_instance" "postgres" {
  identifier            = "animalert-postgres"
  engine                = "postgres"
  engine_version        = "17"
  instance_class        = "db.t4g.micro"
  allocated_storage     = 20
  storage_type          = "gp3"
  max_allocated_storage = 100

  db_name                = var.db_name
  username               = var.db_user
  password               = var.db_password
  port                   = 5432
  publicly_accessible    = false
  multi_az               = false
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.postgres.name

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  deletion_protection        = false
  skip_final_snapshot        = true
  apply_immediately          = true

  tags = {
    Name = "animalert-postgres"
  }
}

###############################################################################
# 14. Outputs
###############################################################################
output "rds_endpoint" {
  value = aws_db_instance.postgres.endpoint
}

output "rds_port" {
  value = aws_db_instance.postgres.port
}

output "rds_db_name" {
  value = var.db_name
}

###############################################################################
# END OF FILE
###############################################################################
