# API Documentation - Osrovnet

## Authentication

All API endpoints require authentication unless otherwise specified. Use token-based authentication.

### Get Authentication Token

```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}'
```

Include the token in subsequent requests:

```bash
curl -H "Authorization: Token your_token_here" http://localhost:8000/api/endpoint/
```

## Network Security API

### Network Scans

#### List all scans
```http
GET /api/network/scans/
```

#### Create a new scan
```http
POST /api/network/scans/
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "scan_type": "full",
  "ports": "1-1000"
}
```

#### Get scan details
```http
GET /api/network/scans/{scan_id}/
```

### Network Hosts

#### List discovered hosts
```http
GET /api/network/hosts/
```

#### Get host details
```http
GET /api/network/hosts/{host_id}/
```

### Vulnerabilities

#### List vulnerabilities
```http
GET /api/network/vulnerabilities/
```

## Threat Intelligence API

### Threat Feeds

#### List threat feeds
```http
GET /api/threats/feeds/
```

#### Create threat feed
```http
POST /api/threats/feeds/
Content-Type: application/json

{
  "name": "Custom Feed",
  "url": "https://example.com/feed.json",
  "feed_type": "json",
  "active": true
}
```

### IOCs (Indicators of Compromise)

#### List IOCs
```http
GET /api/threats/iocs/
```

#### Create IOC
```http
POST /api/threats/iocs/
Content-Type: application/json

{
  "indicator": "192.168.1.100",
  "type": "ip",
  "threat_level": "high",
  "description": "Suspicious IP address"
}
```

## Response Formats

### Success Response
```json
{
  "status": "success",
  "data": {
    // Response data
  },
  "meta": {
    "count": 10,
    "next": "http://localhost:8000/api/endpoint/?page=2",
    "previous": null
  }
}
```

### Error Response
```json
{
  "status": "error",
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": ["This field is required"]
    }
  }
}
```

## Rate Limiting

- API calls are limited to 1000 requests per hour per user
- Network scan endpoints are limited to 10 requests per minute
- Threat analysis endpoints are limited to 100 requests per hour

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid or missing token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |