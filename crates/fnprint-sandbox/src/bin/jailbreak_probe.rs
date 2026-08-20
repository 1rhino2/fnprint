// manual jail probe, also driven by the jail self-test. locks the process down
// then exercises one behavior chosen by argv:
//   "socket" -> catastrophic syscall, must be hard-killed (SIGSYS), never prints
//               REACHED-AFTER-SOCKET.
//   "open"   -> opening a real file must be denied (EPERM) but NOT kill the
//               process. exit 0 only if the open failed; exit 3 if it somehow
//               succeeded (a containment hole).
//   "ok"     -> allowed compute+write path, exit 0.
use std::process::exit;

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    fnprint_sandbox::lock_down_worker().expect("lockdown");
    println!("locked");
    match which.as_str() {
        "socket" => {
            let _ = std::net::TcpStream::connect("127.0.0.1:9");
            println!("REACHED-AFTER-SOCKET"); // must not print if seccomp works
        }
        "open" => match std::fs::File::open("/etc/passwd") {
            Ok(_) => {
                // the jail failed to contain a file read
                exit(3);
            }
            Err(_) => {
                // soft-denied as expected, process survived
                exit(0);
            }
        },
        _ => {
            // allowed path: a little compute, write already proven by "locked"
            let s: u64 = (0..1000u64).map(|x| x.wrapping_mul(x)).sum();
            println!("ok {s}");
        }
    }
}
