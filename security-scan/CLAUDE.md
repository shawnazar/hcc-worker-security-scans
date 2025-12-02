# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security Scan Worker is a Python 3.11+ microservice that consumes scan jobs from RabbitMQ and executes Prowler security scans against AWS, GCP, and Azure cloud accounts. It integrates with the HCC Portal Laravel application, sharing its MariaDB database and RabbitMQ instance.

## Commands

```bash
# Install dependencies
uv sync

# Run the worker
uv run security-scan

# Lint
uv run ruff check src/

# Type check
uv run mypy src/

# Run tests
uv run pytest tests/

# Docker build and run
docker compose build
docker compose up -d
docker compose logs -f
```

## Architecture

### Message Processing Flow

1. Laravel app dispatches scan job to `security-scans` RabbitMQ queue
2. `ScanConsumer` receives message, parses Laravel job format (JSON or PHP serialized)
3. Worker decrypts cloud credentials using Laravel-compatible AES-256-CBC
4. Provider sets up environment variables for authentication
5. `ProwlerWrapper` executes security scan using Prowler as a library
6. `ResultProcessor` stores findings in shared database
7. Scan status updated: pending → running → completed/failed

### Key Components

- **Entry point**: `src/security_scan/main.py`
- **Consumer**: `src/security_scan/worker/consumer.py` - RabbitMQ message handling with prefetch=1 for fair dispatch
- **Providers**: `src/security_scan/providers/` - Factory pattern with AWS, GCP, Azure implementations
- **Prowler**: `src/security_scan/scanner/prowler_wrapper.py` - Wraps Prowler library (not CLI)
- **Encryption**: `src/security_scan/db/encryption.py` - Laravel AES-256-CBC decryption with MAC verification

### Provider Authentication

- **AWS**: IAM credentials or cross-account role assumption via STS
- **GCP**: Service account key or Workload Identity Federation (AWS→GCP token exchange)
- **Azure**: Service principal or Federated Identity (AWS→Azure token exchange)

### Database Models (`src/security_scan/db/models.py`)

- `CloudAccount`: Cloud provider account with encrypted credentials
- `Scan`: Security scan execution record with status and filters
- `ScanFinding`: Individual security finding from Prowler

## Design Patterns

- **Factory Pattern**: `ProviderFactory` creates provider instances by name
- **Strategy Pattern**: Each provider implements `BaseProvider` with different auth strategies
- **Pre-acknowledge**: Messages ACKed before processing to prevent infinite redelivery of malformed data
- **Horizontal Scaling**: Unique consumer tags (hostname-uuid) enable multiple worker instances

## Configuration

Uses Pydantic Settings with `.env` file. Key variables: `APP_KEY` (Laravel encryption key), database credentials, RabbitMQ credentials, AWS credentials (for role assumption), Sentry DSN.
