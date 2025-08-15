package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
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
	serviceName       = getenvDefault("SERVICE_NAME", "aayush_test_6")
	collectorURL      = getenvRequired("OTEL_EXPORTER_OTLP_ENDPOINT") // Must be set for SigNoz Cloud
	accessToken       = os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")       // Example: signoz-access-token=<token>
	ordersProcessed   metric.Int64Counter
	httpRequestsTotal metric.Int64Counter
	httpDuration      metric.Float64Histogram
)

// getenvDefault returns env var value or a default
func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// getenvRequired ensures a required env var is set
func getenvRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		logrus.Fatalf("Environment variable %s must be set for SigNoz Cloud", key)
	}
	return v
}

// initTracer configures tracing over gRPC with TLS
func initTracer() func(context.Context) error {
	exporter, err := otlptracegrpc.New(
		context.Background(),
		otlptracegrpc.WithEndpoint(collectorURL),
		otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlptracegrpc.WithHeaders(map[string]string{
			"signoz-access-token": accessToken,
		}),
	)
	if err != nil {
		logrus.Fatalf("Failed to create trace exporter: %v", err)
	}

	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		logrus.Fatalf("Could not set resources: %v", err)
	}

	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resources),
		),
	)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)
	return exporter.Shutdown
}

// initLogger configures logging over gRPC with TLS
func initLogger() func(context.Context) error {
	ctx := context.Background()

	logExporter, err := otlploggrpc.New(
		ctx,
		otlploggrpc.WithEndpoint(collectorURL),
		otlploggrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlploggrpc.WithHeaders(map[string]string{
			"signoz-access-token": accessToken,
		}),
	)
	if err != nil {
		logrus.Fatalf("Failed to create log exporter: %v", err)
	}

	logProvider := otel_log.NewLoggerProvider(
		otel_log.WithProcessor(otel_log.NewBatchProcessor(logExporter)),
	)
	// Bridge Logrus -> OTel Logs
	hook := otellogrus.NewHook(serviceName, otellogrus.WithLoggerProvider(logProvider))
	logrus.AddHook(hook)

	return logProvider.Shutdown
}

// initMeter configures metrics over gRPC with TLS
func initMeter() func(context.Context) error {
	ctx := context.Background()

	// Define resource with service metadata
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		logrus.Errorf("Failed to create resource: %v", err)
		os.Exit(1)
	}

	// Create OTLP metric exporter over gRPC + TLS
	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpoint(collectorURL),
		otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlpmetricgrpc.WithHeaders(map[string]string{
			"signoz-access-token": os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"),
		}),
	)
	if err != nil {
		logrus.Errorf("Failed to create metric exporter: %v", err)
		os.Exit(1)
	}

	// Create MeterProvider with shorter export interval (10s instead of 60s)
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(10*time.Second),
		)),
		sdkmetric.WithResource(res),
	)

	// Register global meter provider
	otel.SetMeterProvider(meterProvider)

	// Create counter
	meter := meterProvider.Meter(serviceName)
	ordersProcessed, err = meter.Int64Counter(
		"orders_processed_total",
		metric.WithDescription("Total number of orders processed"),
	)
	if err != nil {
		logrus.Errorf("Failed to create counter: %v", err)
		os.Exit(1)
	}

	httpRequestsTotal, err = meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		logrus.Errorf("Failed to create http_requests_total counter: %v", err)
		os.Exit(1)
	}

	httpDuration, err = meter.Float64Histogram(
		"http_duration_seconds",
		metric.WithDescription("Duration of HTTP requests in seconds"),
	)
	if err != nil {
		logrus.Errorf("Failed to create http_duration_seconds histogram: %v", err)
		os.Exit(1)
	}

	// Push initial zero so it shows in SigNoz immediately
	ordersProcessed.Add(ctx, 0)

	return meterProvider.Shutdown
}

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

func metricsMiddleware(c *gin.Context) {
	start := time.Now()
	c.Next()
	duration := time.Since(start).Seconds()
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

func createOrderHandler(c *gin.Context) {
	ctx := c.Request.Context()
	tr := otel.Tracer(serviceName)

	_, dbSpan := tr.Start(ctx, "db_process_order")
	startDB := time.Now()

	rand.Seed(time.Now().UnixNano())
	status := "success"
	if rand.Float64() < 0.9 {
		time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)
		dbSpan.AddEvent("Order creation succeeded")
	} else {
		status = "failure"
		time.Sleep(time.Duration(200+rand.Intn(300)) * time.Millisecond)
		dbSpan.AddEvent("Order creation failed", oteltrace.WithAttributes(attribute.String("reason", "simulated-failure")))
		err := fmt.Errorf("simulated order creation failure")
		dbSpan.RecordError(err)
		dbSpan.SetStatus(codes.Error, err.Error())
	}
	dbSpan.SetAttributes(attribute.Float64("db.duration_ms", float64(time.Since(startDB).Milliseconds())))
	dbSpan.End()

	ordersProcessed.Add(ctx, 1, metric.WithAttributes(attribute.String("status", status)))

	if status == "success" {
		logrus.WithContext(ctx).Info("Order created successfully")
		c.String(http.StatusOK, "Order created successfully")
	} else {
		oteltrace.SpanFromContext(ctx).SetAttributes(attribute.String("error", "true"))
		logrus.WithContext(ctx).Error("Failed to create order")
		c.String(http.StatusInternalServerError, "Internal Server Error")
	}
}

func checkInventoryHandler(c *gin.Context) {
	ctx := c.Request.Context()
	rand.Seed(time.Now().UnixNano())
	delay := time.Duration(200+rand.Intn(600)) * time.Millisecond
	time.Sleep(delay)
	logrus.WithContext(ctx).Infof("Inventory checked, delay_ms: %d", delay.Milliseconds())
	c.String(http.StatusOK, "Inventory checked in %v", delay)
}

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	cleanupTracer := initTracer()
	defer cleanupTracer(context.Background())

	cleanupLogger := initLogger()
	defer cleanupLogger(context.Background())

	cleanupMeter := initMeter()
	defer cleanupMeter(context.Background())

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(otelgin.Middleware(serviceName))
	r.Use(metricsMiddleware)

	r.POST("/createOrder", createOrderHandler)
	r.GET("/checkInventory", checkInventoryHandler)

	logrus.WithField("service", serviceName).Info("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		logrus.Errorf("Server failed: %v", err)
	}
}
