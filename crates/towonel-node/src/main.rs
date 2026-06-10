#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Boxed because the node's run future is tens of KB.
    Box::pin(towonel_node::run()).await
}
