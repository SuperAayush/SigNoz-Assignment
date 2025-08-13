# Go Order Processing Service with OpenTelemetry Instrumentation

This repository contains a simple Go-based HTTP service simulating an order-processing system, fully instrumented with OpenTelemetry for traces, metrics, and logs. The telemetry data is exported to an OTLP collector (e.g., SigNoz) for observability.

<img width="1341" height="423" alt="image" src="https://github.com/user-attachments/assets/1676c6ce-7bb5-4b1a-a6a6-7a4f625d405d" />

## Features

* HTTP endpoints: `/createOrder` (POST) and `/checkInventory` (GET).
* Simulates order creation with a 90% success rate and random failures.
* Variable delays in inventory check to mimic downstream dependencies.
* OpenTelemetry instrumentation:
   * Automatic tracing for HTTP requests via Gin middleware.
   * Manual spans for database simulation in `/createOrder`.
   * Custom metrics: `orders_processed_total`, `http_server_requests_total`, `http_server_duration_seconds`, and `go.runtime.goroutines` gauge.
   * Structured logging with Logrus, bridged to OpenTelemetry logs for correlation with traces.

## Prerequisites

* Go 1.22 or higher.
* Docker and Docker Compose (for running SigNoz).
* SigNoz installed locally (follow the SigNoz installation guide).
* Environment variables:
   * `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP collector endpoint (default: localhost:4317 for gRPC).
   * `OTEL_EXPORTER_OTLP_HEADERS`: SigNoz access token if required.
   * `INSECURE_MODE`: Set to true for insecure connections (default: secure).
   * `SERVICE_NAME`: Service name (default: aayush_test_4).

## Installation

1. Clone the repository:

```bash
git clone https://github.com/scaler-aayush/SigNoz-Assignment.git
```

2. Install dependencies:

```bash
go mod tidy
```

## Running the Application

For SigNoz Cloud:

```bash
SERVICE_NAME=<service_name> INSECURE_MODE=<true/false> OTEL_EXPORTER_OTLP_HEADERS=signoz-access-token=<SIGNOZ-INGESTION-TOKEN> OTEL_EXPORTER_OTLP_ENDPOINT=ingest.{region}.signoz.cloud:443 go run main.go
```

For Local Setup:
```bash
SERVICE_NAME=<service_name> INSECURE_MODE=<true/false> OTEL_EXPORTER_OTLP_HEADERS=signoz-access-token=<SIGNOZ-INGESTION-TOKEN> OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317 go run main.go
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
<img width="1813" height="980" alt="image" src="https://github.com/user-attachments/assets/a2b0e801-d346-4fd6-a23c-9f375c603e1e" />


## Troubleshooting

* Ensure the OTLP endpoint is reachable.
* Check logs for exporter initialization errors.
* Verify SigNoz ingestion by querying the dashboard after generating requests.
