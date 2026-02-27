use actix_web::web;
use context_service::{AppState, DocumentStore, RateLimiter, run_server};
use dotenv::dotenv;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let secret = std::env::var("API_SECRET").unwrap_or_default();
    let rate_limit_seconds = std::env::var("RATE_LIMIT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let app_state = web::Data::new(AppState {
        secret,
        rate_limiter: RateLimiter::new(rate_limit_seconds),
        documents: DocumentStore::new(),
    });

    run_server(("0.0.0.0", 8080), app_state).await
}
