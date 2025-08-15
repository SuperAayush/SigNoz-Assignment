# Go Order Processing Service with OpenTelemetry Instrumentation

This repository contains a simple Go-based HTTP service simulating an order-processing system, fully instrumented with OpenTelemetry for traces, metrics, and logs. The telemetry data is exported to an OTLP collector (e.g., SigNoz) for observability.

<img width="1341" height="423" alt="image" src="https://github.com/user-attachments/assets/1676c6ce-7bb5-4b1a-a6a6-7a4f625d405d" />

## Features

### HTTP Endpoints:
- POST `/createOrder` — Simulates order creation with a 90% success rate and random simulated failures.
- GET `/checkInventory` — Simulates an inventory check with random delay to mimic downstream dependencies.

### OpenTelemetry Instrumentation:
- Automatic tracing for HTTP requests via `otelgin` middleware.
- Manual spans for database simulation in `/createOrder`.
- Metrics:
    - `orders_processed_total` — Count of orders processed, labeled with status.
    - `http_requests_total` — Total HTTP requests received.
    - `http_duration_seconds` — Request duration histogram.
- Logging:
    - Structured JSON logging using Logrus.
    - Logrus bridged to OpenTelemetry logs with automatic trace_id and span_id injection for correlation.
- GRPC + TLS Export for traces, metrics, and logs directly to SigNoz Cloud or any OTLP-compliant backend.
- Configurable service name and collector endpoint via environment variables.

## Prerequisites

- Go 1.22 or higher.
- SigNoz Cloud account (or self-hosted SigNoz instance with OTLP gRPC enabled).
- Environment variables:
    - `OTEL_EXPORTER_OTLP_ENDPOINT` — SigNoz OTLP gRPC endpoint (e.g., ingest.{region}.signoz.cloud:443).
    - `OTEL_EXPORTER_OTLP_HEADERS` — SigNoz Cloud [access token](https://signoz.io/docs/ingestion/signoz-cloud/keys/) in format:
        ```ini=
        signoz-access-token=<your-token>
        ```
    - `SERVICE_NAME` — Name of this service (default: aayush_test_6).
- No local collector required — the app connects directly to SigNoz Cloud over gRPC with TLS.

## Installation

1. Clone the repository:

```bash
https://github.com/SuperAayush/SigNoz-Assignment.git
cd SigNoz-Assignment
```

2. Install dependencies:

```bash
go mod tidy
```

## Running the Application

For SigNoz Cloud:

```bash
SERVICE_NAME=<service_name> INSECURE_MODE=<true/false> OTEL_EXPORTER_OTLP_HEADERS=<SIGNOZ-INGESTION-TOKEN> OTEL_EXPORTER_OTLP_ENDPOINT=ingest.{region}.signoz.cloud:443 go run main.go
```

- Update `<SIGNOZ-INGESTION-TOKEN>` with the [ingestion token](https://signoz.io/docs/ingestion/signoz-cloud/keys/) provided by SigNoz
- Update `ingest.{region}.signoz.cloud:443` with the ingestion endpoint of your region. Refer to the table below for the same.

| Region | Endpoint                   |
| ------ | -------------------------- |
| US     | ingest.us.signoz.cloud:443 |
| IN     | ingest.in.signoz.cloud:443 |
| EU     | ingest.eu.signoz.cloud:443 |

## Testing the Endpoints

* Create an order (90% success, 10% failure):

```bash
curl -X POST http://localhost:8080/createOrder
```

* Check inventory (with 200-800ms delay):

```bash
curl http://localhost:8080/checkInventory
```

Generate traffic to produce telemetry data.

## Viewing Observability Data in SigNoz

* **Traces**: View request paths, including custom `db_process_order` spans with events and attributes.
* **Metrics**: Monitor `orders_processed_total` (by status), HTTP request counts, durations (histograms), and goroutine counts.
* **Logs**: Correlated with traces via `trace_id` and `span_id` and filter by service or severity.
<img width="1814" height="983" alt="image" src="https://github.com/user-attachments/assets/5b15adcf-8cec-4fac-802f-64a48c272f9e" />

## Troubleshooting

* Ensure the OTLP endpoint is reachable.
* Check logs for exporter initialization errors.
* Verify SigNoz ingestion by querying the dashboard after generating requests.
