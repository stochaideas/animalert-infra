###############################################################################
# Terraform Required Providers
###############################################################################
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40" # make sure you have 5.33+ for managed EBS‑on‑Fargate
    }
  }
}

###############################################################################
# 1. Providers and Variables
###############################################################################
provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "vpc_id" {
  type    = string
  default = "vpc-0f7d15a949f96e201" # CHANGE ME
}

variable "public_subnets" {
  type    = list(string)
  default = [
    "subnet-0eb9d9ee655898647",
    "subnet-0458ee3a121ef69d2"
  ] # CHANGE ME
}

variable "private_subnets" {
  type    = list(string)
  default = [
    "subnet-0eb9d9ee655898647",
    "subnet-0458ee3a121ef69d2"
  ] # CHANGE ME
}

###############################################################################
# 2. S3 Buckets (Images, Logs, Backups)
###############################################################################
resource "aws_s3_bucket" "images" {
  bucket = "animalert-images"  # CHANGE to your unique bucket name
  acl    = "private"
}

resource "aws_s3_bucket" "logs" {
  bucket = "animalert-logs"    # CHANGE to your unique bucket name
  acl    = "private"
}

resource "aws_s3_bucket" "backups" {
  bucket = "animalert-backups" # CHANGE to your unique bucket name
  acl    = "private"
}

###############################################################################
# 3. ECR Repository (to store the Docker image)
###############################################################################
resource "aws_ecr_repository" "web_app_repo" {
  name                 = "animalert-webapp"
  image_tag_mutability = "MUTABLE"
}

###############################################################################
# 4. Networking: Security Groups for ALB and ECS Service
###############################################################################
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "Allow HTTP in"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all out"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_service_sg" {
  name   = "ecs-service-sg"
  vpc_id = var.vpc_id

  ingress {
    description     = "Allow traffic from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

###############################################################################
# 5. Application Load Balancer
###############################################################################
resource "aws_lb" "app_lb" {
  name               = "my-app-lb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.public_subnets

  access_logs {
    bucket  = aws_s3_bucket.logs.bucket
    prefix  = "alb-access-logs"
    enabled = true
  }
}

resource "aws_lb_target_group" "app_tg" {
  name        = "my-app-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"  # For Fargate

  health_check {
    path     = "/"
    interval = 30
  }
}

resource "aws_lb_listener" "app_http_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

###############################################################################
# 6. ECS Cluster (Fargate)
###############################################################################
resource "aws_ecs_cluster" "main" {
  name = "animalert-ecs-cluster"
}

###############################################################################
# 7. IAM Roles for ECS Tasks
###############################################################################
## a) Execution Role (pull images, push logs)

data "aws_iam_policy_document" "ecs_task_execution_assume_role_policy" {
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
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "execution_role_attachment" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

## b) Task Role (app logic access to S3 etc.)

data "aws_iam_policy_document" "ecs_task_role_assume_role_policy" {
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
  assume_role_policy = data.aws_iam_policy_document.ecs_task_role_assume_role_policy.json
}

data "aws_iam_policy_document" "ecs_task_s3_policy_doc" {
  statement {
    sid = "AllowS3Access"
    actions = ["s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.images.arn}/*",
      "${aws_s3_bucket.logs.arn}/*",
      "${aws_s3_bucket.backups.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "ecs_task_s3_policy" {
  name        = "ecsTaskS3Policy"
  description = "Allow ECS tasks to read/write objects in S3"
  policy      = data.aws_iam_policy_document.ecs_task_s3_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_s3_policy_attachment" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_s3_policy.arn
}

###############################################################################
# 8. IAM Infrastructure Role for Managed EBS Volumes
###############################################################################
data "aws_iam_policy_document" "ecs_infra_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
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

resource "aws_iam_role_policy_attachment" "ecs_infra_role_volumes" {
  role       = aws_iam_role.ecs_infra_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForVolumes"
}

###############################################################################
# 9. CloudWatch Log Groups (one‑off resources so they exist before tasks run)
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
# 10. ECS Task Definition (Web App + Postgres, with configure_at_launch volume)
###############################################################################
resource "aws_ecs_task_definition" "web_app_task" {
  family                   = "animalert-web-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  # The volume will be created by the ECS service when it starts the task
  volume {
    name                = "db-volume"
    configure_at_launch = true
  }

  container_definitions = <<DEFINITION
[
  {
    "name": "web-app",
    "image": "${aws_ecr_repository.web_app_repo.repository_url}:latest",
    "essential": true,
    "portMappings": [
      { "containerPort": 80, "protocol": "tcp" }
    ],
    "environment": [
      { "name": "DB_HOST",     "value": "127.0.0.1" },
      { "name": "DB_NAME",     "value": "my_app_db" },
      { "name": "DB_USER",     "value": "myuser" },
      { "name": "DB_PASSWORD", "value": "super-secret" }
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/web-app",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "webapp"
      }
    }
  },
  {
    "name": "database",
    "image": "postgres:14",
    "essential": true,
    "environment": [
      { "name": "POSTGRES_DB",       "value": "my_app_db" },
      { "name": "POSTGRES_USER",     "value": "myuser" },
      { "name": "POSTGRES_PASSWORD", "value": "super-secret" }
    ],
    "mountPoints": [
      { "sourceVolume": "db-volume", "containerPath": "/var/lib/postgresql/data" }
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/db",
        "awslogs-region": "${var.aws_region}",
        "awslogs-stream-prefix": "db"
      }
    }
  }
]
DEFINITION
}

###############################################################################
# 11. ECS Service (Fargate behind ALB) + Managed EBS Volume
###############################################################################
resource "aws_ecs_service" "web_app_service" {
  name             = "animalert-web-app-service"
  cluster          = aws_ecs_cluster.main.arn
  launch_type      = "FARGATE"
  desired_count    = 2
  platform_version = "1.4.0" # 1.4+ required for EBS on Fargate

  task_definition = aws_ecs_task_definition.web_app_task.arn

  network_configuration {
    subnets          = var.private_subnets
    security_groups  = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "web-app"
    container_port   = 80
  }

  # New: service‑managed EBS volume that backs /var/lib/postgresql/data
  volume_configuration {
    name = "db-volume"

    managed_ebs_volume {
      role_arn         = aws_iam_role.ecs_infra_role.arn
      encrypted        = true
      volume_type      = "gp3"
      size_in_gib      = 20
      iops             = 3000
      throughput       = 125
      file_system_type = "ext4"
      delete_on_termination = true
    }
  }

  depends_on = [
    aws_lb_listener.app_http_listener
  ]
}

###############################################################################
# END OF FILE – EFS & Backup resources have been fully removed
###############################################################################
