use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, web};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct RateLimiter {
    limits: Mutex<HashMap<String, u64>>, // IP -> last request timestamp
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            window_seconds,
        }
    }

    fn allow(&self, ip: &str) -> bool {
        if self.window_seconds == 0 {
            return true;
        }

        let now = current_unix_seconds();
        let mut limits = self.limits.lock().expect("rate limiter lock poisoned");
        match limits.get(ip) {
            Some(&last) if now.saturating_sub(last) < self.window_seconds => false,
            _ => {
                limits.insert(ip.to_string(), now);
                true
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub title: Option<String>,
    pub content: String,
}

#[derive(Debug, Default)]
pub struct DocumentStore {
    documents: Mutex<HashMap<String, Document>>,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self {
            documents: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, document: Document) -> Result<(), &'static str> {
        let mut docs = self.documents.lock().expect("document store lock poisoned");
        if docs.contains_key(&document.id) {
            return Err("Document already exists");
        }
        docs.insert(document.id.clone(), document);
        Ok(())
    }

    pub fn read(&self, id: &str) -> Option<Document> {
        let docs = self.documents.lock().expect("document store lock poisoned");
        docs.get(id).cloned()
    }

    pub fn update(&self, id: &str, payload: UpsertDocumentRequest) -> Option<Document> {
        let mut docs = self.documents.lock().expect("document store lock poisoned");
        if let Some(existing) = docs.get_mut(id) {
            existing.title = payload.title;
            existing.content = payload.content;
            return Some(existing.clone());
        }
        None
    }

    pub fn delete(&self, id: &str) -> Option<Document> {
        let mut docs = self.documents.lock().expect("document store lock poisoned");
        docs.remove(id)
    }

    pub fn all(&self) -> Vec<Document> {
        let docs = self.documents.lock().expect("document store lock poisoned");
        docs.values().cloned().collect()
    }
}

#[derive(Debug)]
pub struct AppState {
    pub secret: String,
    pub rate_limiter: RateLimiter,
    pub documents: DocumentStore,
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before UNIX_EPOCH")
        .as_secs()
}

fn verify_hmac(secret: &str, timestamp: u64, signature: &str) -> bool {
    if secret.is_empty() {
        return true;
    }

    let now = current_unix_seconds();
    if now.saturating_sub(timestamp) > 30 {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("invalid hmac key");
    mac.update(format!("timestamp={}", timestamp).as_bytes());
    let expected = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    expected == signature
}

pub async fn get_context(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
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

    if !rate_limiter.allow(&ip) {
        return HttpResponse::TooManyRequests().body("Rate limit exceeded");
    }

    if !verify_hmac(secret, timestamp, signature) {
        return HttpResponse::Unauthorized().body("Invalid HMAC or timestamp");
    }

    let context: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("CTX_"))
        .map(|(k, v)| (k["CTX_".len()..].to_string(), v))
        .collect();

    HttpResponse::Ok().json(context)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContextFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CompressRequest {
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub files: Vec<ContextFile>,
    pub max_tokens: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompressResponse {
    pub summary: String,
    pub compressed_context: String,
    pub estimated_tokens: usize,
    pub truncated: bool,
}

fn estimate_tokens(input: &str) -> usize {
    input.chars().count().div_ceil(4)
}

fn path_priority(path: &str) -> usize {
    let lower = path.to_lowercase();
    if lower.contains("readme") || lower.contains("architecture") {
        0
    } else if lower.contains("cargo.toml") || lower.contains("package.json") {
        1
    } else if lower.starts_with("src/") {
        2
    } else if lower.starts_with("tests/") {
        3
    } else {
        4
    }
}

fn summarize_file(file: &ContextFile) -> String {
    let mut bullets = Vec::new();
    let mut picked = 0usize;

    for line in file.content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("pub struct ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("class ")
            || trimmed.starts_with("interface ")
            || trimmed.starts_with('#')
        {
            bullets.push(format!(
                "- {}",
                trimmed.chars().take(140).collect::<String>()
            ));
            picked += 1;
        }

        if picked >= 8 {
            break;
        }
    }

    if bullets.is_empty() {
        let fallback = file
            .content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .take(5)
            .map(|line| format!("- {}", line.chars().take(140).collect::<String>()))
            .collect::<Vec<_>>();
        bullets.extend(fallback);
    }

    format!("### {}\n{}", file.path, bullets.join("\n"))
}

pub fn compress_context(payload: &CompressRequest) -> CompressResponse {
    let max_tokens = payload.max_tokens.unwrap_or(2000).max(64);

    let mut files = payload.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|f| (path_priority(&f.path), f.path.clone()));

    let mut summary_parts = Vec::new();
    if !payload.context.trim().is_empty() {
        let overview = payload
            .context
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .take(8)
            .collect::<Vec<_>>()
            .join(" ");
        if !overview.is_empty() {
            summary_parts.push(format!("Project overview: {}", overview));
        }
    }

    if !files.is_empty() {
        summary_parts.push(format!(
            "Files included: {} (prioritized toward docs/manifests/src).",
            files.len()
        ));
    }

    let summary = if summary_parts.is_empty() {
        "No input context provided.".to_string()
    } else {
        summary_parts.join("\n")
    };

    let mut composed = vec![format!("## Summary\n{}", summary)];
    for file in files {
        composed.push(summarize_file(file));
    }

    if !payload.context.trim().is_empty() {
        composed.push(format!(
            "## Raw Context Snippet\n{}",
            payload
                .context
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    let draft = composed.join("\n\n");
    let mut truncated = false;
    let compressed_context = if estimate_tokens(&draft) > max_tokens {
        truncated = true;
        let max_chars = max_tokens * 4;
        draft.chars().take(max_chars).collect::<String>()
    } else {
        draft
    };

    let estimated_tokens = estimate_tokens(&compressed_context);

    CompressResponse {
        summary,
        compressed_context,
        estimated_tokens,
        truncated,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateDocumentRequest {
    pub id: String,
    pub title: Option<String>,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpsertDocumentRequest {
    pub title: Option<String>,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RagQueryRequest {
    pub query: String,
    pub top_k: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RagMatch {
    pub id: String,
    pub title: Option<String>,
    pub score: usize,
    pub excerpt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RagQueryResponse {
    pub query: String,
    pub matches: Vec<RagMatch>,
}

fn tokenize(input: &str) -> HashSet<String> {
    input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
        .collect()
}

fn rag_search(documents: &[Document], query: &str, top_k: usize) -> Vec<RagMatch> {
    let query_terms = tokenize(query);

    let mut matches = documents
        .iter()
        .map(|doc| {
            let doc_terms = tokenize(&doc.content);
            let score = query_terms.intersection(&doc_terms).count();
            let excerpt = doc.content.chars().take(220).collect::<String>();
            RagMatch {
                id: doc.id.clone(),
                title: doc.title.clone(),
                score,
                excerpt,
            }
        })
        .filter(|m| m.score > 0)
        .collect::<Vec<_>>();

    matches.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    matches.truncate(top_k);
    matches
}

pub async fn post_context_compress(payload: web::Json<CompressRequest>) -> impl Responder {
    HttpResponse::Ok().json(compress_context(&payload.into_inner()))
}

pub async fn create_document(
    data: web::Data<AppState>,
    payload: web::Json<CreateDocumentRequest>,
) -> impl Responder {
    let document = Document {
        id: payload.id.clone(),
        title: payload.title.clone(),
        content: payload.content.clone(),
    };

    match data.documents.create(document.clone()) {
        Ok(()) => HttpResponse::Created().json(document),
        Err(msg) => HttpResponse::Conflict().body(msg),
    }
}

pub async fn get_document(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    match data.documents.read(&path.into_inner()) {
        Some(document) => HttpResponse::Ok().json(document),
        None => HttpResponse::NotFound().body("Document not found"),
    }
}

pub async fn update_document(
    path: web::Path<String>,
    data: web::Data<AppState>,
    payload: web::Json<UpsertDocumentRequest>,
) -> impl Responder {
    match data
        .documents
        .update(&path.into_inner(), payload.into_inner())
    {
        Some(document) => HttpResponse::Ok().json(document),
        None => HttpResponse::NotFound().body("Document not found"),
    }
}

pub async fn delete_document(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    match data.documents.delete(&path.into_inner()) {
        Some(document) => HttpResponse::Ok().json(document),
        None => HttpResponse::NotFound().body("Document not found"),
    }
}

pub async fn rag_query(
    data: web::Data<AppState>,
    payload: web::Json<RagQueryRequest>,
) -> impl Responder {
    let top_k = payload.top_k.unwrap_or(3).max(1);
    let all_documents = data.documents.all();
    let matches = rag_search(&all_documents, &payload.query, top_k);

    HttpResponse::Ok().json(RagQueryResponse {
        query: payload.query.clone(),
        matches,
    })
}

pub fn app_config(cfg: &mut web::ServiceConfig) {
    cfg.route("/context", web::get().to(get_context))
        .route("/context/compress", web::post().to(post_context_compress))
        .route("/documents", web::post().to(create_document))
        .route("/documents/{id}", web::get().to(get_document))
        .route("/documents/{id}", web::put().to(update_document))
        .route("/documents/{id}", web::delete().to(delete_document))
        .route("/rag/query", web::post().to(rag_query));
}

pub async fn run_server(
    bind_addr: (&str, u16),
    app_state: web::Data<AppState>,
) -> std::io::Result<()> {
    HttpServer::new(move || App::new().app_data(app_state.clone()).configure(app_config))
        .bind(bind_addr)?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressor_obeys_budget() {
        let req = CompressRequest {
            context: "A very long project description".repeat(400),
            files: vec![],
            max_tokens: Some(200),
        };

        let result = compress_context(&req);
        assert!(result.estimated_tokens <= 200);
        assert!(result.truncated);
    }

    #[test]
    fn rag_returns_highest_overlap_first() {
        let documents = vec![
            Document {
                id: "a".to_string(),
                title: Some("alpha".to_string()),
                content: "rust cli github action integration".to_string(),
            },
            Document {
                id: "b".to_string(),
                title: Some("beta".to_string()),
                content: "python flask context service".to_string(),
            },
        ];

        let matches = rag_search(&documents, "rust github integration", 2);
        assert_eq!(matches[0].id, "a");
        assert!(matches[0].score >= 2);
    }
}
