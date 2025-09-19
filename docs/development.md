# Development Guide - Osrovnet

## Setting Up Development Environment

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git
- Docker (optional)

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd osrovnet
   ```

2. **Run setup script**
   ```bash
   ./scripts/dev-setup.sh
   ```

This will automatically set up everything you need for development.

## Manual Setup

### Backend Setup

1. **Create virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Setup database**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   ```

### Frontend Setup

1. **Install dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Start development server**
   ```bash
   npm start
   ```

## Code Standards

### Python (Backend)

- Follow PEP 8 style guide
- Use type hints where possible
- Write docstrings for all functions and classes
- Maximum line length: 88 characters (Black formatter)

```python
def scan_network(target: str, scan_type: str = "tcp") -> Dict[str, Any]:
    """
    Perform network scan on the specified target.
    
    Args:
        target: IP address or CIDR range to scan
        scan_type: Type of scan to perform (tcp, udp, syn)
        
    Returns:
        Dictionary containing scan results
    """
    # Implementation here
    pass
```

### TypeScript (Frontend)

- Use TypeScript for all React components
- Follow React hooks patterns
- Use functional components over class components
- Proper prop typing

```typescript
interface NetworkScanProps {
  target: string;
  onScanComplete: (results: ScanResult[]) => void;
}

const NetworkScan: React.FC<NetworkScanProps> = ({ target, onScanComplete }) => {
  // Component implementation
};
```

## Testing

### Backend Tests

```bash
# Run all tests
cd backend
python manage.py test

# Run specific app tests
python manage.py test network_security

# Run with coverage
pip install coverage
coverage run --source='.' manage.py test
coverage report
```

### Frontend Tests

```bash
# Run all tests
cd frontend
npm test

# Run tests with coverage
npm test -- --coverage
```

## Database Migrations

### Creating Migrations

```bash
# Auto-generate migrations
python manage.py makemigrations

# Create empty migration for data migration
python manage.py makemigrations --empty app_name
```

### Applying Migrations

```bash
# Apply all pending migrations
python manage.py migrate

# Apply migrations for specific app
python manage.py migrate app_name
```

## API Development

### Creating New Endpoints

1. **Define models** in `models.py`
2. **Create serializers** in `serializers.py`
3. **Implement views** in `views.py`
4. **Add URL routes** in `urls.py`
5. **Write tests** in `tests.py`

Example:

```python
# models.py
class NetworkScan(models.Model):
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')

# serializers.py
class NetworkScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkScan
        fields = '__all__'

# views.py
class NetworkScanViewSet(viewsets.ModelViewSet):
    queryset = NetworkScan.objects.all()
    serializer_class = NetworkScanSerializer
    permission_classes = [IsAuthenticated]
```

## Frontend Development

### Component Structure

```
src/
├── components/          # Reusable components
│   ├── common/         # Generic components
│   ├── network/        # Network-specific components
│   └── threats/        # Threat intelligence components
├── pages/              # Page components
├── hooks/              # Custom React hooks
├── services/           # API service functions
├── types/              # TypeScript type definitions
└── utils/              # Utility functions
```

### State Management

Use React hooks for local state and Context API for global state:

```typescript
// useNetworkScan hook
export const useNetworkScan = () => {
  const [scans, setScans] = useState<NetworkScan[]>([]);
  const [loading, setLoading] = useState(false);
  
  const fetchScans = useCallback(async () => {
    setLoading(true);
    try {
      const response = await networkService.getScans();
      setScans(response.data);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  }, []);
  
  return { scans, loading, fetchScans };
};
```

## Debugging

### Backend Debugging

1. **Use Django Debug Toolbar** (already installed in dev)
2. **Add print statements or logging**
   ```python
   import logging
   logger = logging.getLogger('osrovnet')
   logger.debug('Debug message here')
   ```

3. **Use pdb for breakpoints**
   ```python
   import pdb; pdb.set_trace()
   ```

### Frontend Debugging

1. **Use browser dev tools**
2. **React Developer Tools** extension
3. **Console logging**
   ```typescript
   console.log('Debug data:', data);
   ```

## Performance Optimization

### Backend

- Use database indexes for frequently queried fields
- Implement pagination for large datasets
- Use select_related() and prefetch_related() for Django ORM
- Cache expensive operations with Redis

### Frontend

- Use React.memo() for expensive components
- Implement virtual scrolling for large lists
- Lazy load components with React.lazy()
- Optimize bundle size with code splitting

## Deployment

### Local Development

```bash
# Backend
cd backend
source ../.venv/bin/activate
python manage.py runserver

# Frontend
cd frontend
npm start
```

### Docker Development

```bash
docker-compose -f docker-compose.dev.yml up --build
```

### Production Deployment

```bash
./scripts/deploy.sh deploy
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   lsof -ti:8000 | xargs kill -9  # Kill process on port 8000
   ```

2. **Database connection errors**
   - Check DATABASE_URL in .env
   - Ensure PostgreSQL is running
   - Verify credentials

3. **Frontend build errors**
   ```bash
   rm -rf node_modules package-lock.json
   npm install
   ```

4. **Python import errors**
   - Ensure virtual environment is activated
   - Check PYTHONPATH
   - Verify all dependencies are installed

### Getting Help

- Check the logs: `backend/logs/osrovnet.log`
- Enable DEBUG mode for detailed error messages
- Use the browser's network tab for API issues
- Check the GitHub issues for similar problems