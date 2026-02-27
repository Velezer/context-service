use actix_web::{App, HttpServer, web};
use context_service::{AppState, DocumentStore, RateLimiter, app_config};
use std::process::Command;

#[tokio::test]
async fn cli_compress_and_rag_commands_work_against_live_service() {
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
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let temp = tempfile::tempdir().expect("temp dir");
    let include_path = temp.path().join("README.md");
    std::fs::write(&include_path, "# Title\nRust GitHub Action RAG integration")
        .expect("write include file");

    let bin = env!("CARGO_BIN_EXE_context_cli");
    let base_url = format!("http://{}", addr);

    let create = Command::new(bin)
        .args([
            "--server-url",
            &base_url,
            "create",
            "--id",
            "cli-doc",
            "--content",
            "Rust action workflow with retrieval context",
        ])
        .output()
        .expect("run create command");
    assert!(
        create.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let rag = Command::new(bin)
        .args([
            "--server-url",
            &base_url,
            "rag-query",
            "--query",
            "retrieval rust",
            "--top-k",
            "1",
        ])
        .output()
        .expect("run rag command");
    assert!(
        rag.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rag.stderr)
    );
    let rag_out = String::from_utf8_lossy(&rag.stdout);
    assert!(rag_out.contains("cli-doc"), "stdout: {}", rag_out);

    let compress = Command::new(bin)
        .args([
            "--server-url",
            &base_url,
            "compress",
            "--context",
            "Context for workflow",
            "--include",
            include_path.to_string_lossy().as_ref(),
            "--max-tokens",
            "120",
        ])
        .output()
        .expect("run compress command");
    assert!(
        compress.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&compress.stderr)
    );
    let compress_out = String::from_utf8_lossy(&compress.stdout);
    assert!(
        compress_out.contains("compressed_context"),
        "stdout: {}",
        compress_out
    );

    handle.abort();
}
