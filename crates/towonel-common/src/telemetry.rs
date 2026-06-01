use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider, trace::SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{EnvFilter, prelude::*};

/// Holds active `OTel` providers and shuts them down on drop.
pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            eprintln!("otel tracer shutdown: {e}");
        }
        if let Err(e) = self.logger_provider.shutdown() {
            eprintln!("otel logger shutdown: {e}");
        }
    }
}

/// Initialize the global tracing subscriber.
///
/// If `OTEL_EXPORTER_OTLP_ENDPOINT` is set, `OTel` trace and log providers are
/// wired up via OTLP/HTTP alongside the stdout layer. Returns a guard that
/// flushes and shuts down the providers on drop — keep it alive for the
/// duration of the process.
#[must_use]
pub fn init(service_name: &str, version: &str) -> Option<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,opentelemetry_sdk=off"));

    let providers = try_build_providers(service_name, version);

    if let Some((tracer_provider, logger_provider)) = providers {
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());

        let tracer = opentelemetry::global::tracer(service_name.to_owned());
        let otel_trace_layer = OpenTelemetryLayer::new(tracer);
        let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider).with_filter(
            "info,opentelemetry=off,opentelemetry_sdk=off,opentelemetry_otlp=off,\
             opentelemetry_appender_tracing=off,hyper=off,h2=off,reqwest=off,tonic=off"
                .parse::<EnvFilter>()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        );

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(otel_trace_layer)
            .with(otel_log_layer)
            .init();

        Some(TelemetryGuard {
            tracer_provider,
            logger_provider,
        })
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
        None
    }
}

fn try_build_providers(
    service_name: &str,
    version: &str,
) -> Option<(SdkTracerProvider, SdkLoggerProvider)> {
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err() {
        return None;
    }

    let mut resource =
        Resource::builder().with_attribute(KeyValue::new("service.version", version.to_owned()));
    if std::env::var("OTEL_SERVICE_NAME").is_err() {
        resource = resource.with_service_name(service_name.to_owned());
    }
    let resource = resource.build();

    let span_exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("otel trace exporter init: {e}");
            return None;
        }
    };

    let log_exporter = match opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("otel log exporter init: {e}");
            return None;
        }
    };

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();

    let logger_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
        .with_resource(resource)
        .build();

    Some((tracer_provider, logger_provider))
}
