mod cli;

fn main() {
    if let Err(err) = cli::run() {
        eprintln!("walden: {err:#}");
        std::process::exit(1);
    }
}
