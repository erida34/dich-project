use clap::Parser;

fn main() {
    let cli = dich_cli::Cli::parse();
    if let Err(message) = dich_cli::run(cli) {
        eprintln!("dich: error: {message}");
        std::process::exit(2);
    }
}
