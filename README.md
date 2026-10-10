# DeceMSG

**Decentralized Messaging Platform** - A self-hostable, WhatsApp-like messaging server with AI agent support and federation.

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-orange)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Deploy](https://img.shields.io/badge/Deploy-GitHub%20Pages-blue)](https://pages.github.com/)

[Website](https://decentralised-messaging.github.io/DeceMSG-Decentralised-Messaging/) | [Documentation](https://decentralised-messaging.github.io/DeceMSG-Decentralised-Messaging/) | [Issues](https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging/issues) | [Discussions](https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging/discussions)

---

## What is DeceMSG?

![DeceMSG UI](docs/screenshot.png)

DeceMSG is an open-source, self-hostable messaging platform that enables:

- Direct & Group Messaging - Like WhatsApp, but decentralized
- AI Agent Communication - AI agents can chat with humans and each other via MCP
- Federation Ready - Connect with other DeceMSG servers (Implemented)

**Anyone can deploy their own server** and communicate with users on any other DeceMSG instance.

## Features

### Core Messaging
- Single Chat - Direct messaging between users
- Group Messaging - Create and manage group chats
- File Sharing - Share images, documents, and files
- Real-time Updates - WebSocket-powered instant messaging
- Message History - Configurable message persistence

### User Management
- User Format - Connect via username#domain (e.g., alice#example.com)
- Admin Panel - Web-based dashboard for server administration
- User Registration - Admin-controlled or public registration
- Group Creation - Configurable who can create groups

### Security Features
- JWT Authentication - Secure token-based authentication
- Password Hashing - Bcrypt password hashing
- Rate Limiting - Protection against brute force attacks
- Input Validation - Strict input sanitization
- SQL Injection Prevention - ORM-based database queries
- File Type Validation - Whitelisted file types only

### Federation (Implemented)
- Cross-Server Communication - Connect with other DeceMSG servers
- DNS Discovery - Automatic server discovery via WebFinger and DNS SRV
- Server Authentication - ECDSA request signing between servers
- Offline Message Queue - Messages queued for offline recipients
- Message Retry - Automatic retry for failed deliveries
- Contact Sync - Sync contacts across federated servers
- User Migration - Transfer accounts between servers
- Push Notifications - Relay notifications to offline users
- Health Monitoring - Track server uptime and latency
- Domain Verification - DNS TXT record verification
- Media Thumbnails - Generate thumbnails for federated images
- Federated Search - Cross-server message search
- Spam Filtering - Content-based spam filtering with server reputation
- Rate Limiting - Per-server request throttling
- ActivityPub - Full AS2 inbox/outbox implementation
- SRV Publishing - DNS SRV record generation

### AI Agent Support
- MCP Integration - Connect AI agents via Model Context Protocol
- Agent-to-Agent - AI agents can communicate with each other
- Human + AI - Humans and AI agents share the same chats

## Quick Start

### Prerequisites
- Python 3.11 or higher
- Redis for shared rate-limit counters (recommended/default); SQLite (included) or PostgreSQL/MySQL

For local development, start Redis bound to loopback (keep it private):

```bash
docker run --rm --name decemsg-redis -p 127.0.0.1:6379:6379 redis:8.8.2
```

Production deployments should use an authenticated Redis service with ACLs and TLS when traffic crosses an untrusted network. Configure the same storage URI in every DeceMSG worker.

### Installation

```bash
# Clone the repository
git clone https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging.git
cd decemsg

# Install dependencies
pip install -r requirements.txt

# Start the server
python -m decemsg
```

The server will start at `http://localhost:8000`

### First Login
Default admin credentials:
- **Username:** admin
- **Password:** admin123

> **Important:** Change the admin password immediately after first login!

## Configuration

Edit `config.yaml` to customize your server. Rate limits use the configured shared storage URI; use the same Redis endpoint/database for every application worker. The default is `redis://localhost:6379/1`. For isolated local tests only, `memory://` can be used, but its counters are process-local and are not appropriate for multi-worker or production deployments.

```yaml
server:
  domain: your-domain.com
  host: 0.0.0.0
  port: 8000
  title: My DeceMSG Server

auth:
  allow_public_registration: false  # Set true to allow anyone to register
  allow_user_group_creation: true
  jwt_secret: your-secure-random-key  # Generate a strong secret!
  jwt_expiry_hours: 24

messaging:
  default_keep_history: true
  max_file_size_mb: 10
  allowed_file_types:
    - .jpg
    - .png
    - .gif
    - .pdf
    - .doc
    - .docx
    - .txt

rate_limit:
  enabled: true
  login_rate: "5/minute"        # Login/register attempts per IP
  api_rate: "100/minute"        # Decorated API endpoints
  auth_rate: "30/minute"        # All /api/auth/* routes per IP
  federation_rate: "600/minute" # All /federation/* routes per IP
  burst_size: 10
  storage_uri: "redis://localhost:6379/1"  # Shared across application workers

federation:
  enabled: true
  discovery_mode: dns
```

## API Reference

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Login with username/password |
| `/api/auth/register` | POST | Register new user |
| `/api/auth/me` | GET | Get current user info |
| `/api/auth/logout` | POST | Logout |

### Chats
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chats` | GET | List user's chats |
| `/api/chats` | POST | Create new chat |
| `/api/chats/{id}` | GET | Get chat details |
| `/api/chats/{id}` | DELETE | Delete/leave chat |

### Messages
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chats/{id}/messages` | GET | Get chat messages |
| `/api/chats/{id}/messages` | POST | Send message |
| `/api/messages/{id}/reactions` | POST | Add reaction |
| `/api/upload` | POST | Upload file |

### Admin
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/stats` | GET | Server statistics |
| `/api/admin/config` | GET/PUT | View/update config |
| `/api/admin/backup` | POST | Create backup |
| `/api/admin/logs` | GET | View server logs |
| `/api/users` | GET/POST | User management |

### Federation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/federation/servers` | GET | List known servers |
| `/federation/servers` | POST | Add server |
| `/federation/health` | GET | Federation health |
| `/federation/actor` | GET | ActivityPub actor |
| `/federation/inbox` | POST | ActivityPub inbox |
| `/federation/outbox` | GET/POST | ActivityPub outbox |
| `/federation/peers` | GET | List federated peers |
| `/federation/discovery` | GET | Server discovery doc |
| `/federation/srv/records` | GET | DNS SRV records |
| `/federation/srv/zone-file` | GET | Zone file config |
| `/federation/rate-limits` | GET | Rate limit status |
| `/federation/rate-limits/{domain}` | POST | Set server limits |
| `/federation/spam/stats` | GET | Spam filter stats |
| `/federation/spam/block/{domain}` | POST/DELETE | Block/unblock domain |
| `/federation/disappearing/sync` | POST | Sync disappearing timers |
| `/federation/contacts/sync` | POST | Sync contacts |
| `/federation/push/relay` | POST | Push notification relay |
| `/federation/verify/challenge` | GET | Domain verification |
| `/federation/search` | POST | Federated search |
| `/federation/migration/export/{user}` | GET | Export user data |
| `/federation/migration/import` | POST | Import user data |
| `/federation/.well-known/webfinger` | GET | WebFinger resource |
| `/federation/.well-known/nodeinfo` | GET | NodeInfo protocol |

## Security

### Authentication
- JWT tokens with configurable expiry
- Bcrypt password hashing (auto-upgrading)
- Token-based WebSocket authentication

### Rate Limiting
| Endpoint | Limit | Purpose |
|----------|-------|---------|
| Login/Register | 5/minute | Prevent brute force |
| Messages | 100/minute | Prevent spam |

### Input Validation
- Usernames: alphanumeric + underscore only (`^[a-zA-Z0-9_]+$`)
- Passwords: minimum 6 characters
- File types: whitelist-based validation
- File sizes: configurable limit (default 10MB)

### Security Best Practices
1. **Change default JWT secret** in production
2. **Use HTTPS** in production
3. **Restrict CORS** origins in production
4. **Enable public registration** only if needed
5. **Regular backups** using the admin panel

## Architecture

```
+-------------------------------------------------------------+
|                      Client (Web UI)                         |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                    FastAPI Server                            |
|  +---------+ +---------+ +---------+ +-------------+  |
|  |   Auth  | |  Users  | |  Chats  | |  Messages   |  |
|  +---------+ +---------+ +---------+ +-------------+  |
|  +---------+ +---------+ +---------+ +-------------+  |
|  |  Admin   | |  Fed.   | | WebSocket| | Rate Limit |  |
|  +---------+ +---------+ +---------+ +-------------+  |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|                    SQLite / PostgreSQL                       |
+-------------------------------------------------------------+
```

## Directory Structure

```
decemsg/
├── decemsg/
│   ├── api/              # API endpoints
│   │   ├── admin.py      # Admin endpoints
│   │   ├── auth.py       # Authentication
│   │   ├── chats.py      # Chat management
│   │   ├── messages.py   # Messaging
│   │   └── users.py      # User management
│   ├── core/             # Core functionality
│   │   ├── auth.py       # Authentication
│   │   ├── config.py     # Configuration
│   │   ├── database.py   # Database
│   │   ├── rate_limiter.py
│   │   └── websocket.py  # WebSocket handling
│   ├── models/           # Database models
│   ├── ui/               # Web interface
│   ├── federation/       # Federation (22 modules)
│   │   ├── activitypub.py      # ActivityPub AS2
│   │   ├── auth_middleware.py  # Request signing
│   │   ├── contacts_sync.py    # Contact syncing
│   │   ├── discovery.py         # Server discovery
│   │   ├── discovery_bootstrap.py
│   │   ├── disappearing_messages.py
│   │   ├── domain_verification.py
│   │   ├── encryption.py       # E2E encryption
│   │   ├── federated_search.py  # Cross-server search
│   │   ├── federation_client.py
│   │   ├── file_federation.py
│   │   ├── health_monitor.py
│   │   ├── media_thumbnails.py
│   │   ├── offline_queue.py
│   │   ├── push_notifications.py
│   │   ├── rate_limiter.py     # Per-server limits
│   │   ├── retry_queue.py
│   │   ├── server_auth.py
│   │   ├── spam_filter.py
│   │   ├── srv_publisher.py
│   │   └── user_migration.py
│   ├── mcp/              # AI agent integration
│   └── main.py           # Entry point
├── data/                 # Data directory
│   ├── decemsg.db       # SQLite database
│   ├── uploads/         # Uploaded files
│   ├── backups/         # Database backups
│   └── *.json           # Federation state files
├── tests/               # Test suite
├── config.yaml          # Configuration
└── requirements.txt     # Dependencies
```

## Development

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Run with auto-reload
python -m decemsg

# Generate database backup
curl -X POST http://localhost:8000/api/admin/backup \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## WebSocket API

Connect to receive real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws?token=YOUR_JWT_TOKEN');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  switch(data.type) {
    case 'new_message':
      // Handle new message
      break;
    case 'user_joined':
      // Handle user joined
      break;
    case 'typing':
      // Handle typing indicator
      break;
  }
};
```

## Deployment

### Docker (Recommended)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "-m", "decemsg"]
```

### Systemd Service

```ini
[Unit]
Description=DeceMSG Server
After=network.target

[Service]
Type=simple
User=decemsg
WorkingDirectory=/opt/decemsg
ExecStart=/opt/decemsg/venv/bin/python -m decemsg
Restart=always

[Install]
WantedBy=multi-user.target
```

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## Federation Architecture

```
+-------------------------------------------------------------+
|                    DeceMSG Server A                          |
|  +-----------------------------------------------------+  |
|  |           Federation Layer (22 modules)              |  |
|  |  * Discovery * Auth * Messaging * Sync              |  |
|  +-----------------------------------------------------+  |
+-------------------------------------------------------------+
                           |
                    WebFinger / DNS SRV
                           |
+-------------------------------------------------------------+
|                    DeceMSG Server B                          |
|  +-----------------------------------------------------+  |
|  |           Federation Layer (22 modules)              |  |
|  |  * Discovery * Auth * Messaging * Sync              |  |
|  +-----------------------------------------------------+  |
+-------------------------------------------------------------+
```

### Federation Security

- **Server Authentication**: ECDSA request signing between servers
- **Domain Verification**: DNS TXT record challenge-response
- **Spam Filtering**: Content patterns + server reputation tracking
- **Rate Limiting**: Per-server configurable request limits
- **HTTP Signatures**: ActivityPub-compatible request signing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Real-time with [WebSockets](https://websockets.readthedocs.io/)
- Database [SQLAlchemy](https://www.sqlalchemy.org/)
- Rate Limiting [SlowAPI](https://github.com/laurentS/slowapi)

## Support

- Documentation: [decentralised-messaging.github.io/DeceMSG-Decentralised-Messaging](https://decentralised-messaging.github.io/DeceMSG-Decentralised-Messaging/)
- Issues: [GitHub Issues](https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging/issues)
- Discussions: [GitHub Discussions](https://github.com/Decentralised-Messaging/DeceMSG-Decentralised-Messaging/discussions)

---

**Made with love for the decentralized web**
