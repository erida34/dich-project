use clap::FromArgMatches;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let json = args.iter().any(|arg| arg == "--json");
    let language = dich_cli::Language::select(&args);
    let matches = match dich_cli::Cli::command_for_language(language).try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) if error.use_stderr() && json => {
            let err = dich_cli::CliError {
                code: "invalid_arguments",
                message: "invalid command-line arguments",
                trace: Vec::new(),
            };
            eprintln!("{}", err.render_for(true, language));
            std::process::exit(err.exit_code());
        }
        Err(error) => error.exit(),
    };
    let cli = match dich_cli::Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let language = cli.lang;
    if let Err(error) = dich_cli::run(cli) {
        let code = error.exit_code();
        eprintln!("{}", error.render_for(json, language));
        std::process::exit(code);
    }
}
