# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "osrovnet" {
  name       = "${var.cluster_name}-cache-subnet"
  subnet_ids = module.vpc.private_subnets

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-cache-subnet"
  })
}

# ElastiCache Security Group
resource "aws_security_group" "elasticache" {
  name_prefix = "${var.cluster_name}-elasticache"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "Redis from EKS"
    from_port   = 6379
    to_port     = 6379
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
    Name = "${var.cluster_name}-elasticache-sg"
  })
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "osrovnet" {
  family = "redis7.x"
  name   = "${var.cluster_name}-redis-params"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  tags = var.tags
}

# ElastiCache Replication Group
resource "aws_elasticache_replication_group" "osrovnet" {
  replication_group_id         = "${var.cluster_name}-redis"
  description                  = "Redis cluster for Osrovnet"

  node_type                    = var.elasticache_node_type
  port                         = 6379
  parameter_group_name         = aws_elasticache_parameter_group.osrovnet.name

  num_cache_clusters           = var.elasticache_num_cache_nodes
  automatic_failover_enabled   = var.elasticache_num_cache_nodes > 1
  multi_az_enabled            = var.elasticache_num_cache_nodes > 1

  subnet_group_name           = aws_elasticache_subnet_group.osrovnet.name
  security_group_ids          = [aws_security_group.elasticache.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result

  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-redis"
  })
}

# Random password for Redis
resource "random_password" "redis_password" {
  length  = 32
  special = false
}

# Store Redis password in AWS Secrets Manager
resource "aws_secretsmanager_secret" "redis_password" {
  name = "${var.cluster_name}/redis/password"
  description = "Redis password for Osrovnet ElastiCache"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redis_password" {
  secret_id = aws_secretsmanager_secret.redis_password.id
  secret_string = jsonencode({
    password = random_password.redis_password.result
    host     = aws_elasticache_replication_group.osrovnet.primary_endpoint_address
    port     = aws_elasticache_replication_group.osrovnet.port
  })
}

# CloudWatch Log Group for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/aws/elasticache/${var.cluster_name}-redis/slow-log"
  retention_in_days = 7

  tags = var.tags
}