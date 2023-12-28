use axum::{
    body::Body,
    extract::Extension,
    http::{Request, Response, StatusCode},
    routing::{get, post},
    Json, Router,
};
use std::{sync::Arc, time::Duration};
use tower_http::trace::TraceLayer;
use tracing::{error, info, Span};
use tracing_subscriber::{filter, fmt, EnvFilter};

#[derive(serde::Deserialize)]
struct LogConfig {
    log_level: String,
}

#[derive(serde::Serialize)]
struct ApiResponse {
    message: String,
}

pub fn enable_ansi() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::io::stderr().is_terminal()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup tracing
    let filter_layer = filter::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let tracing_builder = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter_layer)
        .with_span_events(fmt::format::FmtSpan::FULL)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_writer(std::io::stderr)
        .with_ansi(enable_ansi())
        .with_timer(fmt::time::ChronoUtc::rfc_3339())
        .with_filter_reloading();

    let handle = tracing_builder.reload_handle();
    let subscriber = tracing_builder.finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    // Setup SocketAddr to bind into Axum server
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    let listner = tokio::net::TcpListener::bind(&addr).await?;

    let handle_arc = Arc::new(handle.clone());

    // Setup TraceLayer from tower-http
    let trace_layer = TraceLayer::new_for_http()
        .on_request(trace_layer_on_request)
        .on_response(trace_layer_on_response);

    let app = Router::new()
        .route("/ready", get(readiness))
        .route(
            "/envfilter",
            post(|Json(config): Json<LogConfig>| async move {
                let filter_exp = config.log_level.clone();
                match handle.reload(EnvFilter::new(&filter_exp)) {
                    Ok(_) => {
                        // Print the new filter
                        info!("Trace filter updated to {:?}", filter_exp);
                        (
                            StatusCode::OK,
                            Json(ApiResponse {
                                message: "Trace filter updated".to_string(),
                            }),
                        )
                    }
                    Err(e) => {
                        error!("Failed to update trace filter: {}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse {
                                message: format!("Failed to update trace filter: {}", e),
                            }),
                        )
                    }
                }
            }),
        )
        // .layer(trace_layer)
        .layer(TraceLayer::new(
            tower_http::classify::StatusInRangeAsFailures::new(400..=599).into_make_classifier(),
        ))
        .layer(trace_layer)
        .layer(Extension(Arc::new(handle_arc)));

    tracing::info!("listening on: {:?}", &addr);
    axum::serve(listner, app).await?;
    Ok(())
}

fn trace_layer_on_request(_request: &Request<Body>, _span: &Span) {
    tracing::trace!("Got request")
}

fn trace_layer_on_response(response: &Response<Body>, latency: Duration, span: &Span) {
    span.record(
        "latency",
        tracing::field::display(format!("{}μs", latency.as_micros())),
    );
    span.record("status", tracing::field::display(response.status()));
    tracing::trace!("Responded");
}

async fn readiness() -> Response<Body> {
    tracing::debug!("Readiness check");
    Response::new(Body::from("OK"))
}
