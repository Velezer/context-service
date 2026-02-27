use actix_web::{App, HttpServer, web};
use context_service::{
    AppState, Document, DocumentStore, RagQueryResponse, RateLimiter, app_config,
};

#[tokio::test]
async fn crud_and_rag_query_work_end_to_end() {
    let app_state = web::Data::new(AppState {
        secret: String::new(),
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

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build client");

    let create_response = client
        .post(format!("http://{}/documents", addr))
        .json(&serde_json::json!({
            "id": "doc-rust",
            "title": "Rust integration",
            "content": "Rust CLI mode for GitHub Action integration with RAG support"
        }))
        .send()
        .await
        .expect("create request should succeed");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);

    let read_response = client
        .get(format!("http://{}/documents/doc-rust", addr))
        .send()
        .await
        .expect("read request should succeed");
    let read_payload: Document = read_response.json().await.expect("valid read json");
    assert_eq!(read_payload.id, "doc-rust");

    let update_response = client
        .put(format!("http://{}/documents/doc-rust", addr))
        .json(&serde_json::json!({
            "title": "Rust integration updated",
            "content": "Rust CRUD and retrieval augmented generation implementation"
        }))
        .send()
        .await
        .expect("update request should succeed");
    assert!(update_response.status().is_success());

    let rag_response = client
        .post(format!("http://{}/rag/query", addr))
        .json(&serde_json::json!({"query": "retrieval generation rust", "top_k": 1}))
        .send()
        .await
        .expect("rag query should succeed");
    let rag_payload: RagQueryResponse = rag_response.json().await.expect("valid rag json");
    assert_eq!(rag_payload.matches.len(), 1);
    assert_eq!(rag_payload.matches[0].id, "doc-rust");

    let delete_response = client
        .delete(format!("http://{}/documents/doc-rust", addr))
        .send()
        .await
        .expect("delete request should succeed");
    assert!(delete_response.status().is_success());

    handle.abort();
}
