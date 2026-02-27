use actix_web::{App, HttpServer, web};
use context_service::{AppState, DocumentStore, RateLimiter, app_config};

#[tokio::test]
async fn context_endpoint_rejects_invalid_hmac() {
    let app_state = web::Data::new(AppState {
        secret: "integration-secret".to_string(),
        rate_limiter: RateLimiter::new(0),
        documents: DocumentStore::new(),
    });

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let addr = listener.local_addr().expect("get local addr");

    let server =
        HttpServer::new(move || App::new().app_data(app_state.clone()).configure(app_config))
            .listen(listener)
            .expect("listen")
            .run();

    let handle = tokio::spawn(server);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build client");

    let response = client
        .get(format!("http://{}/context", addr))
        .header("X-Timestamp", ts.to_string())
        .header("Authorization", "bad-signature")
        .send()
        .await
        .expect("request should succeed");

    let status = response.status();
    let body = response.text().await.expect("response text");
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(body.contains("Invalid HMAC or timestamp"), "body: {body}");

    handle.abort();
}
