use actix_web::{App, HttpServer, web};
use context_service::{AppState, DocumentStore, RateLimiter, app_config};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn sign(secret: &str, timestamp: u64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("valid key");
    mac.update(format!("timestamp={timestamp}").as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn context_endpoint_returns_ctx_variables_with_valid_hmac() {
    unsafe {
        std::env::set_var("CTX_APP_NAME", "context-service");
        std::env::set_var("CTX_ENV", "test");
    }

    let secret = "integration-secret".to_string();
    let app_state = web::Data::new(AppState {
        secret: secret.clone(),
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
        .header("Authorization", sign(&secret, ts))
        .send()
        .await
        .expect("request should succeed");

    let status = response.status();
    let body = response.text().await.expect("response text");
    assert!(status.is_success(), "status: {status}, body: {body}");
    assert!(body.contains("APP_NAME"), "body: {body}");
    assert!(body.contains("context-service"), "body: {body}");

    handle.abort();
}
