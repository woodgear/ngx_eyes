use anyhow::Context;
use anyhow::{anyhow, bail, Result};
use object::Object;
use object::ObjectSymbol;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;

#[path = "bpf/.output/tracecon.skel.rs"]
mod tracecon;
use tracecon::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// nginx path
    #[structopt(long, short)]
    nginx: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(nginx_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(nginx_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = TraceconSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;
    let pid = opts.pid.context("must give a pid")?;
    let mut skel = open_skel.load()?;


    let address = get_symbol_address(&opts.nginx, "ngx_http_init_connection")?;
    let _uprobe = skel
        .progs_mut()
        .ngx_http_init_connection_enter()
        .attach_uprobe(false, pid, &opts.nginx, address)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;
    while running.load(Ordering::SeqCst) {}

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn test_get_symbol_address() {
        let ret = get_symbol_address(
            "/home/cong/sm/temp/openresty-wg/nginx/sbin/nginx",
            "ngx_http_init_connection",
        );
        println!("{:?}", ret);
    }
}

