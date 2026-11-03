use clap::Parser;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let json = args.iter().any(|arg| arg == "--json");
    let cli = match dich_cli::Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if error.use_stderr() && json => {
            let err = dich_cli::CliError {
                code: "invalid_arguments",
                message: "invalid command-line arguments",
                trace: Vec::new(),
            };
            eprintln!("{}", err.render(true));
            std::process::exit(err.exit_code());
        }
        Err(error) => error.exit(),
    };
    if let Err(error) = dich_cli::run(cli) {
        let code = error.exit_code();
        eprintln!("{}", error.render(json));
        std::process::exit(code);
    }
}
