use clap::CommandFactory;
use std::{env, fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    let base = PathBuf::from(
        env::args_os()
            .nth(1)
            .unwrap_or_else(|| "packaging/generated".into()),
    );
    let man_dir = base.join("man");
    let completions_dir = base.join("completions");
    fs::create_dir_all(&man_dir)?;
    fs::create_dir_all(&completions_dir)?;
    let cmd = dich_cli::Cli::command();
    clap_mangen::generate_to(cmd.clone(), &man_dir)?;
    for (shell, filename) in [
        (clap_complete::Shell::Bash, "dich.bash"),
        (clap_complete::Shell::Zsh, "_dich"),
        (clap_complete::Shell::Fish, "dich.fish"),
    ] {
        let mut buf = Vec::new();
        clap_complete::generate(shell, &mut cmd.clone(), "dich", &mut buf);
        fs::write(completions_dir.join(filename), buf)?;
    }
    println!("Generated man and completions in {}", base.display());
    Ok(())
}
