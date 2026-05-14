#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // Installing SIGTERM / SIGINT handlers only fails if libc signal
    // registration fails, which is a startup-time environmental bug.
    #[expect(
        clippy::expect_used,
        reason = "libc signal registration is a startup-time environmental bug"
    )]
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    #[expect(
        clippy::expect_used,
        reason = "libc signal registration is a startup-time environmental bug"
    )]
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
