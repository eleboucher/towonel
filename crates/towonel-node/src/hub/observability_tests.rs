use super::test_helpers::TestHub;

async fn get_text(client: &reqwest::Client, url: &str) -> (reqwest::StatusCode, String) {
    let resp = client.get(url).send().await.expect("send");
    let status = resp.status();
    let body = resp.text().await.expect("text body");
    (status, body)
}

#[tokio::test]
async fn metrics_endpoint_exposes_counters() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let (status, body) = get_text(&client, &hub.url("/metrics")).await;

    assert_eq!(status, 200, "metrics body: {body}");
    // Non-labeled metrics are registered eagerly so they always appear.
    // `process_*` come from the `prometheus` crate's process collector and
    // are a sanity check that runtime metrics are actually exported.
    for name in [
        "towonel_hub_entries_accepted",
        "towonel_hub_sse_subscribers_connected",
        "towonel_hub_tenants_total",
        "process_resident_memory_bytes",
        "process_cpu_seconds_total",
        "process_open_fds",
    ] {
        assert!(
            body.contains(name),
            "missing metric `{name}` in /metrics output; got:\n{body}"
        );
    }
}

#[tokio::test]
async fn response_propagates_x_request_id() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(hub.url("/v1/health"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let hdr = resp
        .headers()
        .get("x-request-id")
        .expect("x-request-id header should be set on every response");
    let value = hdr.to_str().expect("header ascii");
    assert!(!value.is_empty(), "x-request-id must not be empty");
}

#[tokio::test]
async fn requests_metric_labels_endpoint_and_status() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Drive a 200 on a matched route.
    let resp = client
        .get(hub.url("/v1/health"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let (_status, metrics_body) = get_text(&client, &hub.url("/metrics")).await;
    // Expect matched-path + status labels to appear literally.
    assert!(
        metrics_body.contains("endpoint=\"/v1/health\""),
        "expected endpoint=/v1/health label in metrics; got:\n{metrics_body}"
    );
    assert!(
        metrics_body.contains("status=\"200\""),
        "expected status=200 label in metrics; got:\n{metrics_body}"
    );
}

#[tokio::test]
async fn rejected_entries_increment_reason_counter() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();

    // Body is not valid CBOR, so the handler records a reject with reason="invalid_cbor".
    let resp = client
        .post(hub.url("/v1/entries"))
        .header("content-type", "application/cbor")
        .body(vec![0xff, 0xff, 0xff])
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);

    let (_status, metrics_body) = get_text(&client, &hub.url("/metrics")).await;
    assert!(
        metrics_body.contains("reason=\"invalid_cbor\""),
        "expected invalid_cbor label in metrics output; got:\n{metrics_body}"
    );
}
