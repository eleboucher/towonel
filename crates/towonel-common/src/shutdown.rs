#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // Installing SIGTERM / SIGINT handlers only fails if libc signal
    // registration fails, which is a startup-time environmental bug.
    #[allow(clippy::expect_used)]
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    #[allow(clippy::expect_used)]
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => tracing::info!("received SIGTERM"),
        _ = int.recv() => tracing::info!("received SIGINT"),
    }
}

#[cfg(not(unix))]
pub async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("received Ctrl-C");
}
