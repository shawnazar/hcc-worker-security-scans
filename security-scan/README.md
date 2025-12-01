# Security Scan Worker

A Python-based microservice that consumes security scan jobs from RabbitMQ and executes Prowler security scans against cloud providers.

## Overview

This worker integrates with the HCC Portal Laravel application to provide automated security scanning of cloud accounts. It:

- Listens for scan jobs on a RabbitMQ queue
- Decrypts cloud credentials using Laravel-compatible encryption
- Runs Prowler security scans against AWS accounts (GCP/Azure planned)
- Stores scan findings in the shared MariaDB database

## Requirements

- Python 3.11+
- Docker (recommended)
- Access to the HCC Portal's MariaDB database
- Access to the HCC Portal's RabbitMQ instance

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `mariadb` | Database hostname |
| `DB_PORT` | `3306` | Database port |
| `DB_DATABASE` | `laravel` | Database name |
| `DB_USERNAME` | `sail` | Database username |
| `DB_PASSWORD` | `password` | Database password |
| `APP_KEY` | (required) | Laravel APP_KEY for credential decryption |
| `RABBITMQ_HOST` | `rabbitmq` | RabbitMQ hostname |
| `RABBITMQ_PORT` | `5672` | RabbitMQ port |
| `RABBITMQ_USER` | `guest` | RabbitMQ username |
| `RABBITMQ_PASSWORD` | `guest` | RabbitMQ password |
| `RABBITMQ_QUEUE` | `security-scans` | Queue name for scan jobs |
| `PROWLER_OUTPUT_DIR` | `/tmp/prowler` | Prowler output directory |

## Running with Docker

```bash
# Build the image
docker compose build

# Start the worker
docker compose up -d

# View logs
docker compose logs -f
```

## Development

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run the worker
uv run security-scan
```

## Architecture

The worker connects to the same MariaDB and RabbitMQ instances as the Laravel application. When a user initiates a scan in the portal, the Laravel job is dispatched to the `security-scans` queue. This worker picks up the job, runs Prowler, and stores findings back in the database.
