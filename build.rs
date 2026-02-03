use clap::CommandFactory;
use clap_complete::{Shell, generate_to};
use clap_mangen::Man;
use std::env;
use std::fs;
use std::io::Result;
use std::path::Path;

include!("src/cli.rs");

fn main() -> Result<()> {
    // Only generate assets if we are building for release or requested specifically
    println!("cargo:rerun-if-changed=src/cli.rs");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // Create a dummy App to get the definition
    // We need to instantiate the command struct to get the definition
    let cmd = Args::command();

    // 1. Generate Man Pages
    let man = Man::new(cmd.clone());
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    let man_dir = out_path.join("man");
    fs::create_dir_all(&man_dir)?;
    fs::write(man_dir.join("nx53.1"), buffer)?;

    // 2. Generate Shell Completions
    let completions_dir = out_path.join("completions");
    fs::create_dir_all(&completions_dir)?;

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, &mut cmd.clone(), "nx53", &completions_dir)?;
    }

    Ok(())
}
