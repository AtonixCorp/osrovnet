# RDS Subnet Group
resource "aws_db_subnet_group" "osrovnet" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = module.vpc.database_subnets

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-db-subnet-group"
  })
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "PostgreSQL from EKS"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-rds-sg"
  })
}

# RDS Parameter Group
resource "aws_db_parameter_group" "osrovnet" {
  family = "postgres15"
  name   = "${var.cluster_name}-postgres-params"

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  tags = var.tags
}

# RDS Instance
resource "aws_db_instance" "osrovnet" {
  identifier = "${var.cluster_name}-postgres"

  engine                = "postgres"
  engine_version        = "15.4"
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "osrovnet"
  username = "osrovnet_admin"
  password = random_password.db_password.result

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.osrovnet.name
  parameter_group_name   = aws_db_parameter_group.osrovnet.name

  backup_retention_period = var.backup_retention_period
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  monitoring_interval = var.monitoring_enabled ? 60 : 0
  monitoring_role_arn = var.monitoring_enabled ? aws_iam_role.rds_enhanced_monitoring[0].arn : null

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.cluster_name}-postgres-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-postgres"
  })
}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# Store database password in AWS Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name = "${var.cluster_name}/database/password"
  description = "Database password for Osrovnet PostgreSQL"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = aws_db_instance.osrovnet.username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.osrovnet.endpoint
    port     = aws_db_instance.osrovnet.port
    dbname   = aws_db_instance.osrovnet.db_name
  })
}

# RDS Enhanced Monitoring Role
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.monitoring_enabled ? 1 : 0
  name  = "${var.cluster_name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count      = var.monitoring_enabled ? 1 : 0
  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}