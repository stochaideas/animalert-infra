###############################################################################
# Terraform configuration for Animalert stack – HTTPS‑only ALB + port 3000 app
###############################################################################
#  ➜ ALB exposed via HTTPS (443) only
#  ➜ Fargate web‑app container listens on port 3000
#  ➜ Target group/SG updated accordingly
###############################################################################

###############################################################################
# 0. Provider & global data
###############################################################################
provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# 1. Variables
###############################################################################
variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-central-1"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "ebs_volume_size_gb" {
  type    = number
  default = 20
}

# NEW – ACM cert for the HTTPS listener
variable "alb_certificate_arn" {
  description = "ACM certificate ARN for ALB HTTPS listener"
  type        = string
}

###############################################################################
# 2. Networking – VPC, subnets, IGW, NAT
###############################################################################
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "animalert-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "animalert-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = { Name = "animalert-public-${count.index + 1}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "animalert-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count = length(aws_subnet.public)
  vpc   = true
  tags  = { Name = "animalert-nat-eip-${count.index + 1}" }
}

resource "aws_nat_gateway" "nat" {
  count         = length(aws_subnet.public)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.igw]
  tags          = { Name = "animalert-nat-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "animalert-private-${count.index + 1}" }
}

resource "aws_route_table" "private" {
  count  = length(aws_subnet.private)
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
  tags = { Name = "animalert-private-rt-${count.index + 1}" }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

locals {
  public_subnet_ids  = [for s in aws_subnet.public  : s.id]
  private_subnet_ids = [for s in aws_subnet.private : s.id]
}

###############################################################################
# 3. S3 Buckets (Images, Logs, Backups)
###############################################################################
resource "aws_s3_bucket" "images"  { bucket = "animalert-images"  acl = "private" }
resource "aws_s3_bucket" "logs"    { bucket = "animalert-logs"    acl = "private" }
resource "aws_s3_bucket" "backups" { bucket = "animalert-backups" acl = "private" }

###############################################################################
# 4. ECR Repository
###############################################################################
resource "aws_ecr_repository" "web_app_repo" {
  name                 = "animalert-webapp"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

###############################################################################
# 5. Security Groups
###############################################################################
# ALB – HTTPS only
resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# ECS Service – allow +3000 from ALB SG
resource "aws_security_group" "ecs_service_sg" {
  name   = "ecs-service-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "App traffic from ALB"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

###############################################################################
# 6. Application Load Balancer – HTTPS listener
###############################################################################
resource "aws_lb" "app_lb" {
  name               = "animalert-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = local.public_subnet_ids

  access_logs {
    bucket  = aws_s3_bucket.logs.bucket
    prefix  = "alb-access-logs"
    enabled = true
  }
}

resource "aws_lb_target_group" "app_tg" {
  name        = "animalert-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "app_https_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

###############################################################################
# 7. ECS Cluster
###############################################################################
resource "aws_ecs_cluster" "main" { name = "animalert-ecs-cluster" }

###############################################################################
# 8. IAM Roles (execution, task, infra) – unchanged
###############################################################################
#  ... (retain previous IAM blocks) ...
#  For brevity, the IAM blocks are identical to the prior version and have not
#  been removed. Make sure they remain in your working file or modules.

###############################################################################
# 9. ECS Task Definition – app now exposes port 3000
###############################################################################
resource "aws_ecs_task_definition" "web_app_task" {
  family                   = "animalert-web-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  volume {
    name                 = "db-volume"
    configured_at_launch = true
  }

  container_definitions = jsonencode([
    {
      name  = "web-app",
      image = "${aws_ecr_repository.web_app_repo.repository_url}:latest",
      essential = true,
      portMappings = [{ containerPort = 3000, protocol = "tcp" }],
      environment = [
        { name = "DB_HOST",     value = "127.0.0.1" },
        { name = "DB_NAME",     value = "my_app_db" },
        { name = "DB_USER",     value = "myuser" },
        { name = "DB_PASSWORD", value = "super-secret" }
      ],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/web-app",
          awslogs-region        = var.aws_region,
          awslogs-stream-prefix = "webapp"
        }
      }
    },
    {
      name  = "database",
      image = "postgres:14",
      essential = true,
      environment = [
        { name = "POSTGRES_DB",       value = "my_app_db" },
        { name = "POSTGRES_USER",     value = "myuser" },
        { name = "POSTGRES_PASSWORD", value = "super-secret" }
      ],
      mountPoints = [{ sourceVolume = "db-volume", containerPath = "/var/lib/postgresql/data" }],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "/ecs/db",
          awslogs-region        = var.aws_region,
          awslogs-stream-prefix = "db"
        }
      }
    }
  ])
}

###############################################################################
# 10. ECS Service – update container port & listener dep
###############################################################################
resource "aws_ecs_service" "web_app_service" {
  name                    = "animalert-web-app-service"
  cluster                 = aws_ecs_cluster.main.arn
  launch_type             = "FARGATE"
  platform_version        = "1.4.0"
  desired_count           = 2
  task_definition         = aws_ecs_task_definition.web_app_task.arn
  enable_ecs_managed_tags = true

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.ecs_service_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "web-app"
    container_port   = 3000
  }

  volume_configuration {
    name = "db-volume"
    managed_ebs_volume {
      role_arn        = aws_iam_role.ecs_infra_role.arn
      encrypted       = true
      volume_type     = "gp3"
      size_in_gb      = var.ebs_volume_size_gb
      iops            = 3000
      throughput      = 125
      filesystem_type = "ext4"
    }
  }

  depends_on = [aws_lb_listener.app_https_listener]
}

###############################################################################
# 11. CloudWatch Log Groups
###############################################################################
resource "aws_cloudwatch_log_group" "web_app_lg" { name = "/ecs/web-app" retention_in_days = 7 }
resource "aws_cloudwatch_log_group" "db_lg"      { name = "/ecs/db"      retention_in_days = 7 }

###############################################################################
# 12. Outputs
###############################################################################
output "alb_dns_name"      { value = aws_lb.app_lb.dns_name }
output "alb_https_url"     { value = "https://${aws_lb.app_lb.dns_name}" }
