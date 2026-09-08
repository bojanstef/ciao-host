use tracing::level_filters::LevelFilter;
use tracing_subscriber::{filter::Targets, prelude::*};

#[tokio::main]
async fn main() {
    // Upstream transport logs can contain addressing diagnostics. Phase 0 writes only
    // Ciao-owned, redacted events by default.
    //
    // RUST_LOG overrides that default so a failure that only reports its category can be asked
    // for its reason without a rebuild. Unset — which is every normal run — leaves the filter
    // exactly as it was, and an unparseable value falls back to it rather than to silence.
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| value.parse::<Targets>().ok())
        .unwrap_or_else(|| {
            Targets::new()
                .with_default(LevelFilter::OFF)
                .with_target("ciao_host", LevelFilter::INFO)
        });
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false),
        )
        .try_init();

    if let Err(error) = ciao_host::cli::run().await {
        eprintln!("ciao: {error:#}");
        std::process::exit(1);
    }
}
