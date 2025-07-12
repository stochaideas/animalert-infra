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

data "aws_security_group" "console_sg" {
  id = "sg-0f11eaaeb0db450e5"        
}
provider "aws" {
  region = var.aws_region
}
variable "phone_recipients" {
  type    = list(string)
  default = ["+40741028697"]   # E.164 format
}
variable "phone_recipients_stage" {
  type    = list(string)
  default = ["+40741028697"]   # E.164 format
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
  default = "my_app_db"
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

variable "email_pass" {
  type      = string
  sensitive = true
}

variable "email_pass_stage" {
 type      = string
  sensitive = true
}

variable "site_origin" {
  type    = string
  default = "https://anim-alert.org"
}

variable "stage_origin" {
  type    = string
  default = "https://stage.anim-alert.org"
}


variable "local_origin" {
  type    = string
  default = "http://localhost:3000"
}
variable "clerk_publish_key_prod" {
  type = string
  default = "CLERK_K3Y"
}

variable "clerk_secret_key_prod" {
  type = string
  default = "CLERK_K3Y33"
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

variable "clerk_publish_key_stage" {
  type = string
  default = "CLERK_K3Y"
}

variable "clerk_secret_key_stage" {
  type = string
  default = "CLERK_K3Y33"
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
data "aws_acm_certificate" "eco" {
  domain      = "eco-alert.org"   # ⇦ new domain
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
resource "aws_kms_key" "s3_default" {
  description             = "CMK for S3 default encryption (Animalert buckets)"
  enable_key_rotation     = false
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "images" {
  bucket = "animalert-images"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "logs" {
  bucket = "animalert-logs"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "backups" {
  bucket = "animalert-backups"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "images_stage" {
  bucket = "animalert-images-stage"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "logs_stage" {
  bucket = "animalert-logs-stage"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "backups_stage" {
  bucket = "animalert-backups-stage"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "pdf_stage" {
  bucket = "animalert-pdfs-stage"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket" "pdfs" {
  bucket = "animalert-pdfs-prod"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.s3_default.id
      }
    }
  }

  lifecycle { prevent_destroy = true }
}

###############################################################################
# S3 – block all public access on every bucket
###############################################################################

resource "aws_s3_bucket_public_access_block" "images" {
  bucket = aws_s3_bucket.images.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pdfs" {
  bucket = aws_s3_bucket.pdfs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────── STAGE buckets ───────────────

resource "aws_s3_bucket_public_access_block" "images_stage" {
  bucket = aws_s3_bucket.images_stage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "logs_stage" {
  bucket = aws_s3_bucket.logs_stage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "backups_stage" {
  bucket = aws_s3_bucket.backups_stage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pdf_stage" {
  bucket = aws_s3_bucket.pdf_stage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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

resource "aws_s3_bucket_cors_configuration" "cors_images" {
  bucket = aws_s3_bucket.images.id

  cors_rule {
    id              = "web-and-local"
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = [
      var.site_origin,
    ]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}
resource "aws_s3_bucket_cors_configuration" "cors_images_stage" {
  bucket = aws_s3_bucket.images_stage.id
  cors_rule {
    id              = "web-and-local"
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = [
      var.stage_origin,
      var.local_origin
    ]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}
resource "aws_s3_bucket_cors_configuration" "cors_pdfs_stage" {
  bucket = aws_s3_bucket.pdf_stage.id
  cors_rule {
    id              = "web-and-local"
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = [
      var.stage_origin,
      var.local_origin
    ]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}
resource "aws_s3_bucket_cors_configuration" "cors_pdf" {
  bucket = aws_s3_bucket.pdfs.id

  cors_rule {
    id              = "web-and-local"
    allowed_methods = ["PUT", "POST", "GET", "HEAD"]
    allowed_origins = [
      var.site_origin,
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

   # Allow HTTP
  ingress {
    description = "HTTP in"
    from_port   = 80
    to_port     = 80
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

resource "aws_security_group_rule" "db_from_console_sg" {
  type                     = "ingress"
  description              = "Postgres from console-created EC2s"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.db_sg.id        # target (DB) SG
  source_security_group_id = data.aws_security_group.console_sg.id
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
  lifecycle {
    prevent_destroy = true      
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

# HTTPS listener (production)
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

resource "aws_lb_listener_certificate" "eco_cert" {
  listener_arn    = aws_lb_listener.https.arn   # reuse the existing HTTPS listener
  certificate_arn = data.aws_acm_certificate.eco.arn
}

# HTTP listener that redirects to HTTPS
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
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
###############################################################################
# 9-bis.  IAM role **only for the STAGE ECS tasks**
###############################################################################

# ---- 1.  Trust relationship (allow ECS to assume the role) ------------------
data "aws_iam_policy_document" "ecs_task_stage_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_stage_role" {
  name               = "ecsTaskStageRole"                    # distinct name
  assume_role_policy = data.aws_iam_policy_document.ecs_task_stage_assume_role.json
}

# ---- 2.  S3-only policy – limited to *_stage buckets ------------------------
data "aws_iam_policy_document" "ecs_task_stage_s3_policy_doc" {
  statement {
    sid     = "AllowStageS3Access"
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.images_stage.arn}/*",
      "${aws_s3_bucket.logs_stage.arn}/*",
      "${aws_s3_bucket.backups_stage.arn}/*",
      "${aws_s3_bucket.pdf_stage.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "ecs_task_stage_s3_policy" {
  name   = "ecsTaskStageS3Policy"
  policy = data.aws_iam_policy_document.ecs_task_stage_s3_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_stage_s3_policy_attachment" {
  role       = aws_iam_role.ecs_task_stage_role.name
  policy_arn = aws_iam_policy.ecs_task_stage_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "ecs_task_stage_publish_sns" {
  role       = aws_iam_role.ecs_task_stage_role.name
  policy_arn = aws_iam_policy.ecs_task_publish_sns.arn
}


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
      "${aws_s3_bucket.backups.arn}/*",
      "${aws_s3_bucket.pdfs.arn}/*"
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
        },
        {
          name  = "NODEMAILER_SERVICE",
          value = "gmail"
        },
        {
          name  = "EMAIL_ADMIN",
          value = "ancbp.cluj@gmail.com"
        },
        {
          name  = "EMAIL_USER",
          value = "ancbp.cluj@gmail.com"
        },
        {
          name  = "EMAIL_PASS",
          value = var.email_pass
        },
        {
          name  = "EMAIL_FROM",
          value = "AnimAlert <ancbp.cluj@gmail.com>"
        },
        {  
          name = "NODE_ENV",
          value = "production"
        },
        {
          name  = "SNS_TOPIC_ARN"
          value = aws_sns_topic.sms_alerts.arn
        },
        {
          name = "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
          value = var.clerk_publish_key_prod
        },
        {
          name = "CLERK_SECRET_KEY",
          value = var.clerk_secret_key_prod
        },
        {
          name = "AWS_S3_PDF_BUCKET_NAME",
          value = "animalert-pdfs-prod"
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
  task_role_arn            = aws_iam_role.ecs_task_stage_role.arn

  container_definitions = jsonencode([
    {
      name      = "web-app-stage",
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:latest_stage",  # changed tag
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
          name  = "NODE_ENV",
          value = "test"
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
        },
        {
          name  = "NODEMAILER_SERVICE",
          value = "gmail"
        },
        {
          name  = "EMAIL_ADMIN",
          value = "animalert@googlegroups.com"
        },
        {
          name  = "EMAIL_USER",
          value = "ancbp.cluj@gmail.com"
        },
        {
          name  = "EMAIL_PASS",
          value = var.email_pass
        },
        {
          name  = "EMAIL_FROM",
          value = "AnimAlert Staging <ancbp.cluj@gmail.com>"
        },
        {
          name  = "SNS_TOPIC_ARN"
          value = aws_sns_topic.sms_alerts_stage.arn
        },
        {
          name = "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
          value = var.clerk_publish_key_stage
        },
        {
          name = "CLERK_SECRET_KEY",
          value = var.clerk_secret_key_stage
        },
        {
          name = "AWS_S3_PDF_BUCKET_NAME",
          value = "animalert-pdfs-stage"
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
  lifecycle {
    prevent_destroy = true      
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
  deletion_protection = true 
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
  skip_final_snapshot        = true
  apply_immediately          = true
  tags = {
    Name = "animalert-postgres"
  }
}


###NEW DB###

resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS at-rest encryption (animalert)"
  deletion_window_in_days = 10
  enable_key_rotation     = false

  tags = {
    Name = "animalert-rds-key"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/animalert/rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "random_password" "rds" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "rds_master" {
  name                    = "animalert/postgres/master"
  description             = "Master credentials for animalert Postgres"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.rds.arn
}

resource "aws_secretsmanager_secret_version" "rds_master" {
  secret_id     = aws_secretsmanager_secret.rds_master.id
  secret_string = jsonencode({
    username = var.db_user
    password = random_password.rds.result
  })
}

resource "aws_db_parameter_group" "postgres" {
  name        = "animalert-postgres-params"
  family      = "postgres17"
  description = "Enforce SSL and raise security posture"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "postgres-production" {
  identifier                          = "animalert-postgres-prod"
  engine                              = "postgres"
  engine_version                      = "17"
  instance_class                      = "db.t4g.micro"
  allocated_storage                   = 20
  storage_type                        = "gp3"
  max_allocated_storage               = 100
  deletion_protection                 = true
  db_name                             = var.db_name
  username                            = var.db_user
  password                            = random_password.rds.result
  port                                = 5432
  publicly_accessible                 = false
  multi_az                            = true
  vpc_security_group_ids              = [aws_security_group.db_sg.id]
  db_subnet_group_name                = aws_db_subnet_group.postgres.name
  kms_key_id                          = aws_kms_key.rds.arn
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  parameter_group_name                = aws_db_parameter_group.postgres.name
  ca_cert_identifier                  = "rds-ca-ecc384-g1"
  backup_retention_period             = 7
  auto_minor_version_upgrade          = true
  skip_final_snapshot                 = true
  apply_immediately                   = true

  tags = {
    Name = "animalert-postgres-prod"
  }
}

output "db_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the master credentials"
  value       = aws_secretsmanager_secret.rds_master.arn
  sensitive   = true
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
# 15. AWS WAF v2 – Web ACL + Bot Control + Global Rate Limit
###############################################################################

resource "aws_wafv2_web_acl" "alb_waf" {
  name        = "animalert-alb-waf"
  description = "WAF protecting the ALB"
  scope       = "REGIONAL"                   # use CLOUDFRONT for edge-wide ACLs

  default_action {
      allow {
      
      } 
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "animalert-alb-waf"
    sampled_requests_enabled   = true
  }

  # ────────────────────────── ❶ Global rate-based rule ──────────────────────────
  rule {
    name     = "Global-IP-RateLimit"
    priority = 0                      # evaluate first

    action {
      block {}                        # or captcha / challenge / count
    }

    statement {
      rate_based_statement {
        limit              = 500     # requests per 5-minute window
        aggregate_key_type = "IP"     # count per source IPv4/IPv6 address

        # (Recommended) respect the real client IP when behind ALB/CF
        forwarded_ip_config {
          header_name       = "X-Forwarded-For"
          fallback_behavior = "MATCH"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ip-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # ────────────────────────── ❷ AWS-managed rule groups ─────────────────────────
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action { 
      none {
      
      } 
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-rule-set"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action { 
    none {
    
    }
  }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWS-AWSManagedRulesBotControlRuleSet"
    priority = 3

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action { 
      none {
      
          } 
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "bot-control"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_association" "alb_waf_assoc" {
  resource_arn = aws_lb.app_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb_waf.arn
}


###############################################################################
# 16. (disable currently) WAF logging to the existing S3 “logs” bucket
###############################################################################

 #resource "aws_wafv2_web_acl_logging_configuration" "alb_waf_logging" {
 #  resource_arn            = aws_wafv2_web_acl.alb_waf.arn
 #  log_destination_configs = ["${aws_s3_bucket.logs.arn}"]
#}


############################################################
# 17. AWS SNS
############################################################


# 1. CloudWatch Logs group that will hold the delivery records
resource "aws_cloudwatch_log_group" "sms_delivery" {
  name              = "/aws/sns/sms-delivery"
  retention_in_days = 30           # keep 30 days; adjust to taste
}

data "aws_iam_policy_document" "sns_logs_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sns_delivery_status" {
  name               = "snsSmsDeliveryStatus"
  assume_role_policy = data.aws_iam_policy_document.sns_logs_trust.json
}

data "aws_iam_policy_document" "sns_logs_write" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.sms_delivery.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "sns_delivery_status" {
  role   = aws_iam_role.sns_delivery_status.id
  policy = data.aws_iam_policy_document.sns_logs_write.json
}

# 4. Account-wide SMS preferences — now with logging enabled
resource "aws_sns_sms_preferences" "global" {
  default_sms_type                      = "Promotional"   # keep your current values
  default_sender_id                     = "AnimAlert"
  monthly_spend_limit                   = "20"

  # NEW: hook up the role & tell SNS what fraction of successes to log
  delivery_status_iam_role_arn          = aws_iam_role.sns_delivery_status.arn
  delivery_status_success_sampling_rate = 100  # 0-100 (%). 100 = log every success
}

#    Only needed if you want a *different* sampling-rate for one topic.
resource "aws_sns_topic" "sms_alerts" {
  name = "sms-alerts"

  delivery_status_iam_role_arn          = aws_iam_role.sns_delivery_status.arn
  delivery_status_success_sampling_rate = 100
}

resource "aws_sns_topic" "sms_alerts_stage" {
  name = "sms-alerts-stage"

  delivery_status_iam_role_arn          = aws_iam_role.sns_delivery_status.arn
  delivery_status_success_sampling_rate = 100
}

resource "aws_sns_topic" "sms_alerts" {
  name = "sms-alerts"
}
resource "aws_sns_topic" "sms_alerts_stage" {
  name = "sms-alerts-stage"
}
resource "aws_sns_sms_preferences" "global" {
  default_sms_type  = "Promotional"     # or "Promotional"
  default_sender_id = "AnimAlert"             # 1–11 alphanumeric chars
  monthly_spend_limit = "20"              # USD
}
# These attributes map 1-to-1 with the console settings :contentReference[oaicite:0]{index=0}

resource "aws_sns_topic_subscription" "sms" {
  for_each  = toset(var.phone_recipients)
  topic_arn = aws_sns_topic.sms_alerts.arn
  protocol  = "sms"
  endpoint  = each.key
}
resource "aws_sns_topic_subscription" "sms_stage" {
  for_each  = toset(var.phone_recipients_stage)
  topic_arn = aws_sns_topic.sms_alerts_stage.arn
  protocol  = "sms"
  endpoint  = each.key
}
data "aws_iam_policy_document" "sns_publish" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.sms_alerts.arn, aws_sns_topic.sms_alerts_stage.arn]
  }
}

resource "aws_iam_policy" "sns_publish" {
  name   = "sns-publish-sms-alerts"
  policy = data.aws_iam_policy_document.sns_publish.json
}

output "sms_topic_arn" {
  value = aws_sns_topic.sms_alerts.arn
}
output "sms_topic_arn_stage" {
  value = aws_sns_topic.sms_alerts_stage.arn
}
############################################################
# IAM policy that allows sns:Publish on ONE topic
############################################################
data "aws_iam_policy_document" "ecs_task_publish_sns" {
  statement {
    sid       = "AllowPublishToSmsAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.sms_alerts.arn, aws_sns_topic.sms_alerts_stage.arn]   # <- your topic
  }
}

resource "aws_iam_policy" "ecs_task_publish_sns" {
  name   = "ecs-task-publish-sms-alerts"
  policy = data.aws_iam_policy_document.ecs_task_publish_sns.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_role_publish_sns" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_publish_sns.arn
}

# ECS task definitions – **Drizzle migrations** (one-shot)
###############################################################################
# ───────────── Production ─────────────
resource "aws_ecs_task_definition" "db_migrate_task" {
  family                   = "animalert-db-migrate-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "db-migrate",
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:migrate_latest",
      essential = true,

      command   = ["pnpm","dlx","drizzle-kit","migrate","--yes"],

      environment = [
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
          awslogs-stream-prefix = "db-migrate"
        }
      }
    }
  ])
}

# ───────────── Staging ─────────────
resource "aws_ecs_task_definition" "db_migrate_task_stage" {
  family                   = "animalert-db-migrate-task-stage"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_stage_role.arn

  container_definitions = jsonencode([
    {
      name      = "db-migrate-stage",
      image     = "${aws_ecr_repository.web_app_repo.repository_url}:migrate_latest_stage",
      essential = true,
      command   = ["pnpm","dlx","drizzle-kit","migrate","--yes"],

      environment = [
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
          awslogs-stream-prefix = "db-migrate-stage"
        }
      }
    }
  ])
}

