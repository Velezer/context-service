use actix_web::{App, HttpServer, web};
use context_service::{AppState, CompressResponse, RateLimiter, app_config};

#[tokio::test]
async fn compress_endpoint_returns_budgeted_context() {
    let app_state = web::Data::new(AppState {
        secret: String::new(),
        rate_limiter: RateLimiter::new(0),
    });

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let addr = listener.local_addr().expect("get local addr");

    let server =
        HttpServer::new(move || App::new().app_data(app_state.clone()).configure(app_config))
            .listen(listener)
            .expect("listen")
            .run();

    let handle = tokio::spawn(server);

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build client");
    let body = serde_json::json!({
        "context": "Monorepo service for API and worker".repeat(80),
        "files": [
            {"path":"README.md", "content":"# Project\nThis service orchestrates tasks."},
            {"path":"src/main.rs", "content":"pub fn main() {}\nstruct AppState {}"}
        ],
        "max_tokens": 120
    });

    let response = client
        .post(format!("http://{}/context/compress", addr))
        .json(&body)
        .send()
        .await
        .expect("request should succeed");

    let status = response.status();
    let body_text = response.text().await.expect("response text");
    assert!(status.is_success(), "status: {status}, body: {body_text}");
    let payload: CompressResponse = serde_json::from_str(&body_text).expect("valid response json");
    assert!(payload.estimated_tokens <= 120);
    assert!(payload.compressed_context.contains("## Summary"));

    handle.abort();
}
