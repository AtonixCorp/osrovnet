# 🔒 Osrovnet - Network Security Platform

**Osrovnet** is AtonixCorp's flagship platform for advanced network security, threat intelligence, and resilient infrastructure design. Built for sovereign systems and mission-critical environments, Osrovnet empowers organizations to defend from protocol to perimeter with precision, insight, and autonomy.

## 🚀 Features

### 🛡️ Network Security
- Real-time network monitoring and analysis
- Advanced port scanning and vulnerability assessment
- Network topology mapping and visualization
- Intrusion detection and prevention systems
- Traffic analysis and pattern recognition

### 🎯 Threat Intelligence
- Real-time threat feed integration
- IOC (Indicators of Compromise) management
- Threat hunting and analysis tools
- Automated threat response systems
- Threat landscape visualization

### 🏗️ Infrastructure Resilience
- Infrastructure health monitoring
- Automated backup and recovery systems
- High availability configuration
- Disaster recovery planning
- Performance optimization

## 🛠️ Technology Stack

### Backend
- **Django 5.2** - Web framework
- **Django REST Framework** - API development
- **PostgreSQL** - Primary database
- **Redis** - Caching and message broker
- **Celery** - Asynchronous task processing
- **Python-nmap** - Network scanning
- **Scapy** - Packet manipulation
- **Shodan** - Internet-wide scanning data

### Frontend
- **React 18** with **TypeScript**
- **Material-UI (MUI)** - Component library
- **React Router** - Navigation
- **Axios** - HTTP client
- **Recharts** - Data visualization

### Infrastructure
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **Nginx** - Reverse proxy (production)
- **Gunicorn** - WSGI server

## 📋 Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Docker & Docker Compose** (for containerized deployment)
- **PostgreSQL** (for production)
- **Redis** (for caching and Celery)

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

Run the automated development setup script:

```bash
./scripts/dev-setup.sh
```

This script will:
- Set up Python virtual environment
- Install all dependencies
- Configure the database
- Create a superuser account
- Start development servers

### Option 2: Manual Setup

#### 1. Clone and Setup Environment

```bash
git clone <repository-url>
cd osrovnet

# Backend setup
python3 -m venv .venv
source .venv/bin/activate
cd backend
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration

# Frontend setup
cd ../frontend
npm install
```

#### 2. Database Setup

```bash
cd backend
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

#### 3. Start Development Servers

```bash
# Terminal 1 - Backend
cd backend
source ../.venv/bin/activate
python manage.py runserver 8000

# Terminal 2 - Frontend
cd frontend
npm start
```

## 🐳 Docker Deployment

### Development with Docker

```bash
docker-compose -f docker-compose.dev.yml up --build
```

### Production Deployment

```bash
# Use the deployment script
./scripts/deploy.sh deploy

# Or manually
docker-compose up --build -d
```

## 📁 Project Structure

```
osrovnet/
├── backend/                    # Django backend
│   ├── osrovnet/              # Main Django project
│   ├── core/                  # Core app (authentication, common models)
│   ├── network_security/      # Network security features
│   ├── threat_intelligence/   # Threat intelligence features
│   ├── requirements.txt       # Python dependencies
│   └── .env                   # Environment variables
├── frontend/                  # React frontend
│   ├── src/                   # Source code
│   ├── public/                # Static assets
│   └── package.json           # Node.js dependencies
├── docker/                    # Docker configuration
│   ├── Dockerfile.backend     # Backend container
│   └── Dockerfile.frontend    # Frontend container
├── scripts/                   # Utility scripts
│   ├── dev-setup.sh          # Development setup
│   └── deploy.sh             # Production deployment
├── docs/                      # Documentation
├── docker-compose.yml         # Production compose
├── docker-compose.dev.yml     # Development compose
└── README.md                  # This file
```

## 🔧 Configuration

### Environment Variables

Copy `backend/.env.example` to `backend/.env` and configure:

```env
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/osrovnet

# External APIs
SHODAN_API_KEY=your-shodan-api-key
MAXMIND_LICENSE_KEY=your-maxmind-key

# Network Security Settings
NMAP_TIMEOUT=300
SCAN_RATE_LIMIT=10
MAX_CONCURRENT_SCANS=5
```

## 🎯 API Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `GET /api/auth/user/` - Get current user

### Network Security
- `GET /api/network/scans/` - List network scans
- `POST /api/network/scans/` - Create new scan
- `GET /api/network/hosts/` - List discovered hosts
- `GET /api/network/vulnerabilities/` - List vulnerabilities

### Threat Intelligence
- `GET /api/threats/feeds/` - List threat feeds
- `GET /api/threats/iocs/` - List IOCs
- `POST /api/threats/analyze/` - Analyze threat data

## 🧪 Testing

### Backend Tests
```bash
cd backend
python manage.py test
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 📊 Monitoring & Logging

### Application Logs
- Backend logs: `backend/logs/osrovnet.log`
- Frontend: Browser console and network tab

### Health Checks
- Backend: `http://localhost:8000/health/`
- Database: Built-in Django admin health monitoring

## 🔐 Security Considerations

### Production Security
- Change default SECRET_KEY
- Use strong database passwords
- Enable HTTPS/SSL certificates
- Configure firewall rules
- Regular security updates
- Monitor access logs

### API Security
- Token-based authentication
- Rate limiting on sensitive endpoints
- Input validation and sanitization
- CORS configuration
- SQL injection protection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use TypeScript for React components
- Write tests for new features
- Update documentation as needed
- Use semantic commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏢 About AtonixCorp

AtonixCorp specializes in sovereign systems and mission-critical cybersecurity solutions. Our platforms are designed for organizations that require the highest levels of security, reliability, and autonomy.

## 📞 Support

- **Documentation**: `/docs`
- **Issues**: GitHub Issues
- **Email**: support@atonixcorp.com
- **Website**: https://atonixcorp.com

## 🔄 Changelog

### v1.0.0 (Initial Release)
- Django backend with REST API
- React TypeScript frontend
- Docker containerization
- Network security modules
- Threat intelligence integration
- Basic authentication system

---

**Built with ❤️ by AtonixCorp for sovereign security systems**