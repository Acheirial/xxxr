//! `xxxr` 命令行入口。

use clap::Parser;
use xxxr::cli::{self, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::Version => {
            println!("{}", cli::version_string());
            Ok(())
        }
        Command::Run => {
            let path = args
                .config
                .ok_or_else(|| anyhow::anyhow!("`-c/--config <FILE>` is required for `run`"))?;
            cli::run(&path).await.map_err(anyhow::Error::from)
        }
    }
}
