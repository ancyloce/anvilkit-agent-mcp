package bootstrap

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.uber.org/fx"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
)

// startTracing installs the process's tracer provider from the first
// generation: spans go over OTLP/gRPC to the placed collector (plaintext,
// DEVELOPMENT_ONLY until ENV-03's workload PKI) or nowhere. The gRPC server
// and Control client stats handlers use it through the global provider; the
// stop hook flushes within the stop deadline.
func startTracing(lc fx.Lifecycle, gen config.Generation) error {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if gen.Config.Telemetry.OTLPEndpoint == "" {
		return nil
	}
	exporter, err := otlptracegrpc.New(context.Background(), otlptracegrpc.WithEndpoint(gen.Config.Telemetry.OTLPEndpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		return err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewSchemaless(semconv.ServiceName("anvilkit-agent-mcp"))),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(gen.Config.Telemetry.SampleRatio))),
	)
	otel.SetTracerProvider(provider)
	lc.Append(fx.Hook{OnStop: func(ctx context.Context) error {
		flush, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return provider.Shutdown(flush)
	}})
	return nil
}
