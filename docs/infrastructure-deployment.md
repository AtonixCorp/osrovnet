# 🏗️ Osrovnet Infrastructure Deployment Guide

This guide provides comprehensive instructions for deploying the Osrovnet network security platform using the included infrastructure configurations.

## 📁 Infrastructure Overview

The Osrovnet infrastructure includes:

- **Kubernetes Manifests** - Production-ready Kubernetes deployments
- **Terraform Configurations** - Cloud infrastructure provisioning (AWS)
- **CI/CD Pipelines** - GitHub Actions for automated testing and deployment
- **Monitoring Stack** - Prometheus, Grafana, AlertManager
- **Security Configurations** - RBAC, Network Policies, Security Scanning
- **Helm Charts** - Package management and deployment orchestration

## 🚀 Quick Deployment Options

### Option 1: Helm Chart Deployment (Recommended)

```bash
# Add Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install Osrovnet
cd infrastructure/helm
helm install osrovnet ./osrovnet \
  --namespace osrovnet \
  --create-namespace \
  --values ./osrovnet/values.yaml
```

### Option 2: Raw Kubernetes Manifests

```bash
# Apply Kubernetes manifests
kubectl apply -f infrastructure/kubernetes/
```

### Option 3: Terraform + Kubernetes

```bash
# Deploy infrastructure with Terraform
cd infrastructure/terraform/aws
terraform init
terraform plan
terraform apply

# Then deploy applications
kubectl apply -f ../kubernetes/
```

## 🔧 Detailed Setup Instructions

### Prerequisites

- Kubernetes cluster (v1.25+)
- kubectl configured
- Helm 3.x installed
- Docker registry access
- SSL certificates (optional, can use cert-manager)

### 1. Infrastructure Provisioning with Terraform

#### AWS Infrastructure Setup

```bash
cd infrastructure/terraform/aws

# Copy and customize variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your specific values

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file="terraform.tfvars"

# Apply infrastructure
terraform apply -var-file="terraform.tfvars"

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name osrovnet-cluster
```

#### Terraform Outputs

After successful deployment, Terraform provides:
- EKS cluster endpoint
- RDS database endpoint
- ElastiCache Redis endpoint
- VPC and subnet information
- Security group IDs

### 2. Application Deployment

#### Using Helm Charts

```bash
cd infrastructure/helm

# Customize values
cp osrovnet/values.yaml osrovnet/values-prod.yaml
# Edit values-prod.yaml for your environment

# Install dependencies
helm dependency update osrovnet/

# Deploy Osrovnet
helm install osrovnet ./osrovnet \
  --namespace osrovnet \
  --create-namespace \
  --values ./osrovnet/values-prod.yaml \
  --wait
```

#### Using Raw Manifests

```bash
# Create namespace
kubectl create namespace osrovnet

# Apply configurations in order
kubectl apply -f infrastructure/kubernetes/00-namespace.yaml
kubectl apply -f infrastructure/kubernetes/01-configmaps.yaml
kubectl apply -f infrastructure/kubernetes/02-secrets.yaml
kubectl apply -f infrastructure/kubernetes/03-storage.yaml

# Deploy databases
kubectl apply -f infrastructure/kubernetes/04-postgres.yaml
kubectl apply -f infrastructure/kubernetes/05-redis.yaml

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgres -n osrovnet --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n osrovnet --timeout=300s

# Deploy applications
kubectl apply -f infrastructure/kubernetes/06-backend.yaml
kubectl apply -f infrastructure/kubernetes/07-celery.yaml
kubectl apply -f infrastructure/kubernetes/08-frontend.yaml

# Configure networking
kubectl apply -f infrastructure/kubernetes/09-ingress-network.yaml
```

### 3. Monitoring Setup

```bash
# Create monitoring namespace
kubectl create namespace monitoring

# Deploy monitoring stack
kubectl apply -f infrastructure/monitoring/prometheus.yaml
kubectl apply -f infrastructure/monitoring/prometheus-deployment.yaml
kubectl apply -f infrastructure/monitoring/grafana.yaml
kubectl apply -f infrastructure/monitoring/node-exporter.yaml
kubectl apply -f infrastructure/monitoring/alertmanager.yaml

# Wait for monitoring to be ready
kubectl wait --for=condition=ready pod -l app=prometheus -n monitoring --timeout=300s
kubectl wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=300s
```

### 4. Security Configuration

```bash
# Apply RBAC and security policies
kubectl apply -f infrastructure/security/rbac.yaml
kubectl apply -f infrastructure/security/network-policies.yaml
kubectl apply -f infrastructure/security/security-scanning.yaml
```

## 🔐 Security Configuration

### SSL/TLS Certificates

#### Using cert-manager (Recommended)

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@atonixcorp.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

#### Manual Certificate Installation

```bash
# Create TLS secret with your certificates
kubectl create secret tls osrovnet-tls \
  --cert=path/to/certificate.crt \
  --key=path/to/private.key \
  --namespace osrovnet
```

### Secret Management

Update the secrets in `02-secrets.yaml` with base64-encoded values:

```bash
# Encode secrets
echo -n "your-secret-key" | base64
echo -n "your-database-password" | base64
echo -n "your-redis-password" | base64
```

## 📊 Monitoring and Observability

### Access Monitoring Dashboards

```bash
# Port forward Grafana
kubectl port-forward -n monitoring svc/grafana-service 3000:3000

# Port forward Prometheus
kubectl port-forward -n monitoring svc/prometheus-service 9090:9090

# Port forward AlertManager
kubectl port-forward -n monitoring svc/alertmanager 9093:9093
```

### Default Credentials

- **Grafana**: admin/admin123 (change immediately)
- **Prometheus**: No authentication by default
- **AlertManager**: No authentication by default

## 🔧 Configuration Customization

### Environment Variables

Key configuration options in ConfigMaps:

```yaml
# Backend Configuration
DEBUG: "false"
ALLOWED_HOSTS: "your-domain.com"
LOG_LEVEL: "INFO"
NMAP_TIMEOUT: "300"
SCAN_RATE_LIMIT: "10"
MAX_CONCURRENT_SCANS: "5"

# Frontend Configuration  
REACT_APP_API_URL: "https://api.your-domain.com"
REACT_APP_ENVIRONMENT: "production"
```

### Resource Scaling

#### Horizontal Pod Autoscaling

```bash
# Enable HPA for backend
kubectl autoscale deployment osrovnet-backend \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  --namespace osrovnet

# Enable HPA for frontend
kubectl autoscale deployment osrovnet-frontend \
  --cpu-percent=70 \
  --min=3 \
  --max=6 \
  --namespace osrovnet
```

## 🚨 Troubleshooting

### Common Issues

1. **Pod startup failures**
   ```bash
   kubectl describe pod <pod-name> -n osrovnet
   kubectl logs <pod-name> -n osrovnet
   ```

2. **Database connection issues**
   ```bash
   kubectl exec -it <backend-pod> -n osrovnet -- python manage.py dbshell
   ```

3. **Storage issues**
   ```bash
   kubectl get pvc -n osrovnet
   kubectl describe pvc <pvc-name> -n osrovnet
   ```

### Health Checks

```bash
# Check application health
curl -f https://api.osrovnet.atonixcorp.com/health/
curl -f https://osrovnet.atonixcorp.com/

# Check service status
kubectl get pods,svc,ingress -n osrovnet
kubectl get pods -n monitoring
```

## 🔄 Updates and Maintenance

### Rolling Updates

```bash
# Update backend image
kubectl set image deployment/osrovnet-backend \
  backend=registry.atonixcorp.com/osrovnet/backend:v1.1.0 \
  --namespace osrovnet

# Update frontend image
kubectl set image deployment/osrovnet-frontend \
  frontend=registry.atonixcorp.com/osrovnet/frontend:v1.1.0 \
  --namespace osrovnet
```

### Backup Procedures

```bash
# Database backup
kubectl exec -it <postgres-pod> -n osrovnet -- \
  pg_dump -U osrovnet_user osrovnet > backup.sql

# Redis backup
kubectl exec -it <redis-pod> -n osrovnet -- \
  redis-cli BGSAVE
```

## 📞 Support

For deployment issues or questions:

- **Documentation**: `/docs`
- **Issues**: GitHub Issues
- **Email**: support@atonixcorp.com
- **Monitoring**: Check Grafana dashboards for system health

---

**Osrovnet Infrastructure - Built for Mission-Critical Security Operations**