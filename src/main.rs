use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, web};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

struct RateLimiter {
    limits: Mutex<HashMap<String, u64>>, // IP -> last request timestamp
    window_seconds: u64,
}

impl RateLimiter {
    fn new(window_seconds: u64) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            window_seconds,
        }
    }

    fn allow(&self, ip: &str) -> bool {
        if self.window_seconds == 0 {
            // feature inactive
            return true;
        }

        let now = current_unix_seconds();
        let mut limits = self.limits.lock().unwrap();
        match limits.get(ip) {
            Some(&last) if now.saturating_sub(last) < self.window_seconds => false,
            _ => {
                limits.insert(ip.to_string(), now);
                true
            }
        }
    }
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// HMAC verification with timestamp ±30s
fn verify_hmac(secret: &str, timestamp: u64, signature: &str) -> bool {
    if secret.is_empty() {
        // feature inactive
        return true;
    }

    let now = current_unix_seconds();
    if now.saturating_sub(timestamp) > 30 {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("timestamp={}", timestamp).as_bytes());
    let expected = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    expected == signature
}

// GET /context
async fn get_context(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let secret = &data.secret;
    let rate_limiter = &data.rate_limiter;

    let signature = req
        .headers()
        .get("Authorization")
        .and_then(|s| s.to_str().ok())
        .unwrap_or("");
    let timestamp: u64 = req
        .headers()
        .get("X-Timestamp")
        .and_then(|t| t.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    // Rate limiter check
    if !rate_limiter.allow(&ip) {
        return HttpResponse::TooManyRequests().body("Rate limit exceeded");
    }

    // HMAC check
    if !verify_hmac(secret, timestamp, signature) {
        return HttpResponse::Unauthorized().body("Invalid HMAC or timestamp");
    }

    // Collect CTX_ env vars
    let context: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("CTX_"))
        .map(|(k, v)| (k["CTX_".len()..].to_string(), v))
        .collect();

    HttpResponse::Ok().json(context)
}

struct AppState {
    secret: String,
    rate_limiter: RateLimiter,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let secret = std::env::var("API_SECRET").unwrap_or_default(); // empty = feature inactive

    // Read rate limit from env, default 60 seconds
    let rate_limit_seconds = std::env::var("RATE_LIMIT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0); // 0 = inactive

    let rate_limiter = RateLimiter::new(rate_limit_seconds);

    let app_state = web::Data::new(AppState {
        secret,
        rate_limiter,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/context", web::get().to(get_context))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
