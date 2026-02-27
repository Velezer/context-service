use clap::{Parser, Subcommand};
use context_service::{
    CompressRequest, ContextFile, CreateDocumentRequest, RagQueryRequest, UpsertDocumentRequest,
};
use reqwest::blocking::Client;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "context-cli")]
#[command(about = "CLI mode for context-service GitHub Action integrations")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Compress {
        #[arg(long, default_value = "")]
        context: String,
        #[arg(long)]
        context_file: Option<PathBuf>,
        #[arg(long = "include")]
        include_files: Vec<PathBuf>,
        #[arg(long, default_value_t = 2000)]
        max_tokens: usize,
    },
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        content: String,
        #[arg(long)]
        title: Option<String>,
    },
    Read {
        #[arg(long)]
        id: String,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        content: String,
        #[arg(long)]
        title: Option<String>,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    RagQuery {
        #[arg(long)]
        query: String,
        #[arg(long, default_value_t = 3)]
        top_k: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::builder().no_proxy().build()?;

    match cli.command {
        Commands::Compress {
            context,
            context_file,
            include_files,
            max_tokens,
        } => {
            let mut full_context = context;
            if let Some(path) = context_file {
                full_context = fs::read_to_string(path)?;
            }

            let files = include_files
                .into_iter()
                .map(|path| -> Result<ContextFile, Box<dyn std::error::Error>> {
                    let content = fs::read_to_string(&path)?;
                    Ok(ContextFile {
                        path: path.to_string_lossy().to_string(),
                        content,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let payload = CompressRequest {
                context: full_context,
                files,
                max_tokens: Some(max_tokens),
            };

            let response = client
                .post(format!("{}/context/compress", cli.server_url))
                .json(&payload)
                .send()?;

            print_json(response)?;
        }
        Commands::Create { id, content, title } => {
            let payload = CreateDocumentRequest { id, title, content };
            let response = client
                .post(format!("{}/documents", cli.server_url))
                .json(&payload)
                .send()?;
            print_json(response)?;
        }
        Commands::Read { id } => {
            let response = client
                .get(format!("{}/documents/{}", cli.server_url, id))
                .send()?;
            print_json(response)?;
        }
        Commands::Update { id, content, title } => {
            let payload = UpsertDocumentRequest { title, content };
            let response = client
                .put(format!("{}/documents/{}", cli.server_url, id))
                .json(&payload)
                .send()?;
            print_json(response)?;
        }
        Commands::Delete { id } => {
            let response = client
                .delete(format!("{}/documents/{}", cli.server_url, id))
                .send()?;
            print_json(response)?;
        }
        Commands::RagQuery { query, top_k } => {
            let payload = RagQueryRequest {
                query,
                top_k: Some(top_k),
            };
            let response = client
                .post(format!("{}/rag/query", cli.server_url))
                .json(&payload)
                .send()?;
            print_json(response)?;
        }
    }

    Ok(())
}

fn print_json(response: reqwest::blocking::Response) -> Result<(), Box<dyn std::error::Error>> {
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        eprintln!("request failed with status {}: {}", status, text);
        std::process::exit(1);
    }

    let parsed: Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&parsed)?);
    Ok(())
}
