mod cli;

fn main() {
    if let Err(err) = cli::run() {
        if let Some(exit) = err.downcast_ref::<cli::ForwardExit>() {
            std::process::exit(exit.0);
        }
        eprintln!("walden: {err:#}");
        std::process::exit(1);
    }
}
