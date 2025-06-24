# Gunicorn configuration file for production deployment
import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
backlog = 2048

# Worker processes
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)  # Cap at 4 workers for small instances
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 2
max_requests = 1000
max_requests_jitter = 50

# Restart workers after this many requests, with up to 50 requests variation
preload_app = True  # Load app before forking workers

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = "flask-game-app"

# Server mechanics
daemon = False
pidfile = None
user = None
group = None
tmp_upload_dir = None

# SSL (if using HTTPS)
# keyfile = None
# certfile = None

# Disable access log for health checks to reduce noise
def skip_health_check(record):
    return record.getMessage().find('/health') == -1

# Custom log filter
class HealthCheckFilter:
    def filter(self, record):
        return '/health' not in record.getMessage()

# Apply the filter
import logging
logging.getLogger('gunicorn.access').addFilter(HealthCheckFilter())