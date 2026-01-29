# VERITAS Deployment Guide

Production deployment guide for VERITAS nodes.

## Table of Contents

- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Bare Metal Deployment](#bare-metal-deployment)
- [High Availability](#high-availability)
- [Monitoring](#monitoring)
- [Backup and Recovery](#backup-and-recovery)
- [Security Hardening](#security-hardening)

## Deployment Options

| Method | Best For | Complexity |
|--------|----------|------------|
| Docker Compose | Small deployments, development | Low |
| Kubernetes | Production, scalability | Medium |
| Bare Metal | Maximum performance | High |

## Docker Deployment

### Single Node

```bash
# Create data volume
docker volume create veritas-data

# Run the node
docker run -d \
    --name veritas-node \
    --restart unless-stopped \
    -p 9000:9000 \
    -p 8080:8080 \
    -v veritas-data:/var/lib/veritas \
    -e VERITAS_LOG_LEVEL=info \
    -e VERITAS_LOG_FORMAT=json \
    -e VERITAS_BOOTSTRAP_NODES="$BOOTSTRAP_NODES" \
    ghcr.io/veritas-protocol/veritas-node:latest
```

### Docker Compose (Production)

Create `docker-compose.prod.yml`:

```yaml
version: "3.8"

services:
  veritas-node:
    image: ghcr.io/veritas-protocol/veritas-node:latest
    container_name: veritas-node
    restart: unless-stopped
    ports:
      - "9000:9000"    # P2P
      - "8080:8080"    # Health
    volumes:
      - veritas-data:/var/lib/veritas
    environment:
      - VERITAS_LOG_LEVEL=info
      - VERITAS_LOG_FORMAT=json
      - VERITAS_RELAY_MODE=true
      - VERITAS_METRICS_ENABLED=true
      - VERITAS_BOOTSTRAP_NODES=${BOOTSTRAP_NODES}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}

volumes:
  veritas-data:
  prometheus-data:
  grafana-data:
```

Deploy:

```bash
# Set environment variables
export BOOTSTRAP_NODES="/dns4/bootstrap1.veritas.network/tcp/9000/p2p/..."
export GRAFANA_PASSWORD="secure-password"

# Start services
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose -f docker-compose.prod.yml logs -f veritas-node
```

### Multi-Node Cluster

```yaml
version: "3.8"

services:
  node1:
    image: ghcr.io/veritas-protocol/veritas-node:latest
    container_name: veritas-node-1
    restart: unless-stopped
    ports:
      - "9001:9000"
      - "8081:8080"
    volumes:
      - node1-data:/var/lib/veritas
    environment:
      - VERITAS_BOOTSTRAP_NODES=/ip4/node2/tcp/9000,/ip4/node3/tcp/9000
    networks:
      - veritas-net

  node2:
    image: ghcr.io/veritas-protocol/veritas-node:latest
    container_name: veritas-node-2
    restart: unless-stopped
    ports:
      - "9002:9000"
      - "8082:8080"
    volumes:
      - node2-data:/var/lib/veritas
    environment:
      - VERITAS_BOOTSTRAP_NODES=/ip4/node1/tcp/9000,/ip4/node3/tcp/9000
    networks:
      - veritas-net

  node3:
    image: ghcr.io/veritas-protocol/veritas-node:latest
    container_name: veritas-node-3
    restart: unless-stopped
    ports:
      - "9003:9000"
      - "8083:8080"
    volumes:
      - node3-data:/var/lib/veritas
    environment:
      - VERITAS_BOOTSTRAP_NODES=/ip4/node1/tcp/9000,/ip4/node2/tcp/9000
    networks:
      - veritas-net

networks:
  veritas-net:
    driver: bridge

volumes:
  node1-data:
  node2-data:
  node3-data:
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.20+
- kubectl configured
- Helm 3 (optional)

### Deployment Manifest

Create `veritas-deployment.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: veritas
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: veritas-data
  namespace: veritas
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  storageClassName: fast-ssd
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: veritas-config
  namespace: veritas
data:
  VERITAS_LOG_LEVEL: "info"
  VERITAS_LOG_FORMAT: "json"
  VERITAS_RELAY_MODE: "true"
  VERITAS_METRICS_ENABLED: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: veritas-secrets
  namespace: veritas
type: Opaque
stringData:
  VERITAS_BOOTSTRAP_NODES: "/dns4/bootstrap1.veritas.network/tcp/9000/p2p/..."
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veritas-node
  namespace: veritas
  labels:
    app: veritas-node
spec:
  replicas: 1
  selector:
    matchLabels:
      app: veritas-node
  template:
    metadata:
      labels:
        app: veritas-node
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: veritas-node
          image: ghcr.io/veritas-protocol/veritas-node:latest
          ports:
            - containerPort: 9000
              name: p2p
            - containerPort: 8080
              name: health
            - containerPort: 9090
              name: metrics
          envFrom:
            - configMapRef:
                name: veritas-config
            - secretRef:
                name: veritas-secrets
          volumeMounts:
            - name: data
              mountPath: /var/lib/veritas
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2"
              memory: "4Gi"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: veritas-data
---
apiVersion: v1
kind: Service
metadata:
  name: veritas-node
  namespace: veritas
spec:
  selector:
    app: veritas-node
  ports:
    - name: p2p
      port: 9000
      targetPort: 9000
    - name: health
      port: 8080
      targetPort: 8080
    - name: metrics
      port: 9090
      targetPort: 9090
  type: LoadBalancer
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: veritas-network-policy
  namespace: veritas
spec:
  podSelector:
    matchLabels:
      app: veritas-node
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - ports:
        - port: 9000
          protocol: TCP
        - port: 8080
          protocol: TCP
  egress:
    - {}  # Allow all egress
```

Deploy:

```bash
kubectl apply -f veritas-deployment.yaml

# Check status
kubectl -n veritas get pods
kubectl -n veritas logs -f deployment/veritas-node

# Scale
kubectl -n veritas scale deployment veritas-node --replicas=3
```

### StatefulSet for Validators

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: veritas-validator
  namespace: veritas
spec:
  serviceName: veritas-validator
  replicas: 3
  selector:
    matchLabels:
      app: veritas-validator
  template:
    metadata:
      labels:
        app: veritas-validator
    spec:
      containers:
        - name: veritas-node
          image: ghcr.io/veritas-protocol/veritas-node:latest
          env:
            - name: VERITAS_VALIDATOR_MODE
              value: "true"
          volumeMounts:
            - name: data
              mountPath: /var/lib/veritas
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: fast-ssd
        resources:
          requests:
            storage: 100Gi
```

## Bare Metal Deployment

### System Setup

```bash
# Create user
sudo useradd -r -s /bin/false -d /var/lib/veritas veritas

# Create directories
sudo mkdir -p /var/lib/veritas /var/log/veritas /etc/veritas
sudo chown veritas:veritas /var/lib/veritas /var/log/veritas

# Install binary
sudo cp target/release/veritas-node /usr/local/bin/
sudo chmod +x /usr/local/bin/veritas-node
```

### Systemd Service

```bash
sudo tee /etc/systemd/system/veritas-node.service > /dev/null << 'EOF'
[Unit]
Description=VERITAS Protocol Node
Documentation=https://docs.veritas.network
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=veritas
Group=veritas
ExecStart=/usr/local/bin/veritas-node \
    --data-dir /var/lib/veritas \
    --listen-addr /ip4/0.0.0.0/tcp/9000 \
    --log-level info \
    --log-format json \
    --relay-mode true
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/veritas/node.log
StandardError=append:/var/log/veritas/node.log

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/veritas /var/log/veritas
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable veritas-node
sudo systemctl start veritas-node
```

### Log Rotation

```bash
sudo tee /etc/logrotate.d/veritas << 'EOF'
/var/log/veritas/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 veritas veritas
    postrotate
        systemctl reload veritas-node > /dev/null 2>&1 || true
    endscript
}
EOF
```

## High Availability

### Load Balancer Configuration (HAProxy)

```haproxy
frontend veritas_p2p
    bind *:9000
    mode tcp
    default_backend veritas_nodes_p2p

frontend veritas_health
    bind *:8080
    mode http
    default_backend veritas_nodes_health

backend veritas_nodes_p2p
    mode tcp
    balance roundrobin
    server node1 192.168.1.10:9000 check
    server node2 192.168.1.11:9000 check
    server node3 192.168.1.12:9000 check

backend veritas_nodes_health
    mode http
    balance roundrobin
    option httpchk GET /health
    server node1 192.168.1.10:8080 check
    server node2 192.168.1.11:8080 check
    server node3 192.168.1.12:8080 check
```

## Monitoring

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'veritas'
    static_configs:
      - targets: ['veritas-node:9090']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `veritas_peers_connected` | Number of connected peers |
| `veritas_messages_sent_total` | Total messages sent |
| `veritas_messages_received_total` | Total messages received |
| `veritas_blocks_height` | Current blockchain height |
| `veritas_reputation_score` | Node reputation score |

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Basic health check |
| `GET /ready` | Readiness check |

## Backup and Recovery

### Backup Script

```bash
#!/bin/bash
# backup-veritas.sh

BACKUP_DIR="/backup/veritas"
DATA_DIR="/var/lib/veritas"
DATE=$(date +%Y%m%d_%H%M%S)

# Stop the node gracefully
systemctl stop veritas-node

# Create backup
tar -czf "$BACKUP_DIR/veritas-$DATE.tar.gz" -C "$DATA_DIR" .

# Restart node
systemctl start veritas-node

# Clean old backups (keep 7 days)
find "$BACKUP_DIR" -name "veritas-*.tar.gz" -mtime +7 -delete

echo "Backup completed: veritas-$DATE.tar.gz"
```

### Recovery

```bash
# Stop node
systemctl stop veritas-node

# Restore from backup
tar -xzf /backup/veritas/veritas-YYYYMMDD_HHMMSS.tar.gz -C /var/lib/veritas

# Fix permissions
chown -R veritas:veritas /var/lib/veritas

# Start node
systemctl start veritas-node
```

## Security Hardening

### Firewall Rules

```bash
# UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 9000/tcp comment "VERITAS P2P"
sudo ufw allow 8080/tcp comment "VERITAS Health"
sudo ufw allow from 10.0.0.0/8 to any port 9090 comment "VERITAS Metrics (internal)"
sudo ufw enable
```

### Fail2ban

```ini
# /etc/fail2ban/jail.d/veritas.conf
[veritas]
enabled = true
port = 9000
filter = veritas
logpath = /var/log/veritas/node.log
maxretry = 10
bantime = 3600
```

### TLS Termination (Nginx)

```nginx
upstream veritas_health {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name health.veritas.example.com;

    ssl_certificate /etc/letsencrypt/live/veritas.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/veritas.example.com/privkey.pem;

    location / {
        proxy_pass http://veritas_health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Next Steps

- [Configuration Reference](CONFIGURATION.md) - All options
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
- [Security Guide](../docs/SECURITY.md) - Security best practices
