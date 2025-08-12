package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	otel_log "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"
)

var (
	serviceName     = getenvDefault("SERVICE_NAME", "aayush_test_4")                 // Service name used in telemetry data
	collectorURL    = getenvDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317") // OTLP collector endpoint
	insecure        = os.Getenv("INSECURE_MODE")                                     // Controls TLS/insecure connection
	ordersProcessed metric.Int64Counter                                              // Counter for processed orders

	// Additional application metrics
	httpRequestsTotal metric.Int64Counter         // Counter for HTTP requests
	httpDuration      metric.Float64Histogram     // Histogram for HTTP request durations
	goroutinesGauge   metric.Int64ObservableGauge // Gauge for number of goroutines
)

// getenvDefault returns the value of an environment variable or a default if not set.
func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// initTracer configures OpenTelemetry tracing and returns a cleanup function.
func initTracer() func(context.Context) error {
	var secureOption otlptracegrpc.Option

	// Determine TLS or insecure connection based on INSECURE_MODE
	if strings.ToLower(insecure) == "false" || insecure == "0" || strings.ToLower(insecure) == "f" {
		secureOption = otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	} else {
		secureOption = otlptracegrpc.WithInsecure()
	}

	// Create OTLP trace exporter
	exporter, err := otlptrace.New(
		context.Background(),
		otlptracegrpc.NewClient(
			secureOption,
			otlptracegrpc.WithEndpoint(collectorURL),
			otlptracegrpc.WithHeaders(map[string]string{
				"signoz-access-token": os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"),
			}),
		),
	)
	if err != nil {
		logrus.Errorf("Failed to create trace exporter: %v", err)
		os.Exit(1)
	}

	// Define resource attributes (service name, language, etc.)
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		logrus.Errorf("Could not set resources: %v", err)
		os.Exit(1)
	}

	// Set tracer provider and global propagator
	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()), // Always sample traces for demo
			sdktrace.WithBatcher(exporter),                // Batch export spans
			sdktrace.WithResource(resources),
		),
	)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return exporter.Shutdown
}

// initLogger configures OpenTelemetry logging integration with logrus.
func initLogger() func(context.Context) error {
	// Create OTLP log exporter over HTTP
	logExporter, err := otlploghttp.New(
		context.Background(),
		otlploghttp.WithEndpoint("localhost:4318"),
		otlploghttp.WithHeaders(map[string]string{
			"signoz-access-token": os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"),
		}),
	)
	if err != nil {
		logrus.Errorf("Failed to create log exporter: %v", err)
		os.Exit(1)
	}

	// Set logger provider with batch processor
	logProvider := otel_log.NewLoggerProvider(
		otel_log.WithProcessor(
			otel_log.NewBatchProcessor(logExporter),
		),
	)

	// Add OpenTelemetry hook to logrus
	hook := otellogrus.NewHook(serviceName, otellogrus.WithLoggerProvider(logProvider))
	logrus.AddHook(hook)

	return logProvider.Shutdown
}

// initMeter configures OpenTelemetry metrics and application-specific instruments.
func initMeter() func(context.Context) error {
	var secureOption otlpmetricgrpc.Option

	// Determine TLS or insecure connection for metrics
	if strings.ToLower(insecure) == "false" || insecure == "0" || strings.ToLower(insecure) == "f" {
		secureOption = otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	} else {
		secureOption = otlpmetricgrpc.WithInsecure()
	}

	// Create OTLP metric exporter
	exporter, err := otlpmetricgrpc.New(
		context.Background(),
		otlpmetricgrpc.WithEndpoint(collectorURL),
		secureOption,
		otlpmetricgrpc.WithHeaders(map[string]string{
			"signoz-access-token": os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"),
		}),
	)
	if err != nil {
		logrus.Errorf("Failed to create metric exporter: %v", err)
		os.Exit(1)
	}

	// Resource attributes for metrics
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		logrus.Errorf("Could not set resources: %v", err)
		os.Exit(1)
	}

	// Create and set meter provider
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)), // Push metrics periodically
		sdkmetric.WithResource(resources),
		// Configure histogram buckets for HTTP request duration
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: "http_server_duration_seconds"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			}},
		)),
	)
	otel.SetMeterProvider(meterProvider)

	meter := otel.Meter(serviceName)

	// Create application metrics instruments
	ordersProcessed, err = meter.Int64Counter(
		"orders_processed_total",
		metric.WithDescription("Total number of orders processed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		logrus.Fatalf("Failed to create orders_processed_total counter: %v", err)
	}

	httpRequestsTotal, err = meter.Int64Counter(
		"http_server_requests_total",
		metric.WithDescription("Total number of HTTP server requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		logrus.Fatalf("Failed to create http_server_requests_total counter: %v", err)
	}

	httpDuration, err = meter.Float64Histogram(
		"http_server_duration_seconds",
		metric.WithDescription("Duration of HTTP server requests in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		logrus.Fatalf("Failed to create http_server_duration_seconds histogram: %v", err)
	}

	// Observable gauge for runtime goroutines
	goroutinesGauge, err = meter.Int64ObservableGauge(
		"go.runtime.goroutines",
		metric.WithDescription("Number of goroutines"),
		metric.WithUnit("1"),
	)
	if err != nil {
		logrus.Fatalf("Failed to create go.runtime.goroutines gauge: %v", err)
	}

	// Register callback to update goroutines gauge
	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(goroutinesGauge, int64(runtime.NumGoroutine()))
		return nil
	}, goroutinesGauge)
	if err != nil {
		logrus.Fatalf("Failed to register callback for goroutines gauge: %v", err)
	}

	return meterProvider.Shutdown
}

// LogrusFields extracts trace/span IDs from context for structured logging.
func LogrusFields(ctx context.Context) logrus.Fields {
	span := oteltrace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return logrus.Fields{}
	}
	return logrus.Fields{
		"span_id":  span.SpanContext().SpanID().String(),
		"trace_id": span.SpanContext().TraceID().String(),
	}
}

func main() {
	// Configure logrus to output JSON
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Initialize observability components with deferred cleanup
	cleanupTracer := initTracer()
	defer cleanupTracer(context.Background())

	cleanupLogger := initLogger()
	defer cleanupLogger(context.Background())

	cleanupMeter := initMeter()
	defer cleanupMeter(context.Background())

	// Create new Gin router
	r := gin.New()
	r.Use(gin.Recovery())

	// Automatically create spans for incoming requests
	r.Use(otelgin.Middleware(serviceName))

	// Custom middleware to track request metrics
	r.Use(metricsMiddleware)

	// Routes
	r.POST("/createOrder", createOrderHandler)
	r.GET("/checkInventory", checkInventoryHandler)

	logrus.WithField("service", serviceName).Info("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		logrus.Errorf("Server failed: %v", err)
	}
}

// metricsMiddleware records request count and duration metrics for every request.
func metricsMiddleware(c *gin.Context) {
	start := time.Now()
	c.Next()
	duration := time.Since(start).Seconds()

	// Determine the route path for labeling metrics
	operation := c.FullPath()
	if operation == "" {
		operation = c.Request.URL.Path
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.HTTPRouteKey.String(operation),
		semconv.HTTPRequestMethodKey.String(c.Request.Method),
		semconv.HTTPResponseStatusCodeKey.Int(c.Writer.Status()),
	}

	httpDuration.Record(c.Request.Context(), duration, metric.WithAttributes(attrs...))
	httpRequestsTotal.Add(c.Request.Context(), 1, metric.WithAttributes(attrs...))
}

// createOrderHandler simulates an order creation process with tracing and metrics.
func createOrderHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tr := otel.Tracer(serviceName)

	// Create a child span for the database operation
	_, dbSpan := tr.Start(ctx, "db_process_order")
	startDB := time.Now()

	// Simulate order creation with random success/failure
	rand.Seed(time.Now().UnixNano())
	status := "success"
	if rand.Float64() < 0.9 {
		// Success path with simulated DB delay
		time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)
		dbSpan.AddEvent("Order creation succeeded")
	} else {
		// Failure path with longer delay
		status = "failure"
		time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
		dbSpan.AddEvent("Order creation failed", oteltrace.WithAttributes(attribute.String("reason", "simulated-failure")))
		err := fmt.Errorf("simulated order creation failure")
		dbSpan.RecordError(err)
		dbSpan.SetStatus(codes.Error, err.Error())
	}

	// Record DB operation duration
	dbSpan.SetAttributes(attribute.Float64("db.duration_ms", float64(time.Since(startDB).Milliseconds())))
	dbSpan.End()

	// Increment processed orders counter
	ordersProcessed.Add(ctx, 1, metric.WithAttributes(attribute.String("status", status)))

	// Log outcome with trace/span IDs
	if status == "success" {
		logrus.WithFields(LogrusFields(ctx)).Info("Order created successfully")
		c.String(http.StatusOK, "Order created successfully")
	} else {
		// Mark parent span as error
		oteltrace.SpanFromContext(ctx).SetAttributes(attribute.String("error", "true"))
		logrus.WithFields(LogrusFields(ctx)).Error("Failed to create order")
		c.String(http.StatusInternalServerError, "Internal Server Error")
	}
}

// checkInventoryHandler simulates inventory lookup with random delay.
func checkInventoryHandler(c *gin.Context) {
	ctx := c.Request.Context()
	rand.Seed(time.Now().UnixNano())
	delay := time.Duration(200+rand.Intn(600)) * time.Millisecond
	time.Sleep(delay)
	logrus.WithFields(LogrusFields(ctx)).Infof("Inventory checked, delay_ms: %d", delay.Milliseconds())
	c.String(http.StatusOK, "Inventory checked in %v", delay)
}
