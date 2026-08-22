// manual jail probe, also driven by the jail self-test. locks the process down
// then exercises one behavior chosen by argv:
//   "socket" -> catastrophic syscall, must be hard-killed (SIGSYS), never prints
//               REACHED-AFTER-SOCKET.
//   "open"   -> opening a real file must be denied (EPERM) but NOT kill the
//               process. exit 0 only if the open failed; exit 3 if it somehow
//               succeeded (a containment hole).
//   "mmap_exec"     -> mapping an executable page must be denied (EPERM). exit 0
//               if denied, 3 if an exec page was granted (hole), 4 if a plain
//               read/write mmap wrongly failed (we broke the allowed path).
//   "mprotect_exec" -> flipping a page to executable must be denied. exit 0 if
//               denied, 3 if the flip succeeded (hole), 4 if the setup RW map
//               failed.
//   "ok"     -> allowed compute+write path, exit 0.
use std::process::exit;

// this probe issues raw mmap/mprotect to prove the jail denies executable pages.
// there is no safe-Rust way to request PROT_EXEC, so the calls are unsafe. they
// are trivially sound: anonymous fixed-size maps, no dangling pointers escape,
// and the results are only compared against MAP_FAILED / return code.
#[allow(unsafe_code)]
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
        "mmap_exec" => {
            // asking for an executable page must be denied. we run a no-JIT
            // interpreter, so nothing legit ever needs one.
            let exec = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if exec != libc::MAP_FAILED {
                exit(3); // an executable page was granted: containment hole
            }
            // and a plain read/write mapping must still work, so we know the
            // deny is scoped to PROT_EXEC and didn't just break mmap.
            let rw = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if rw == libc::MAP_FAILED {
                exit(4); // non-exec mmap wrongly denied
            }
            exit(0);
        }
        "mprotect_exec" => {
            // map read/write, then try to flip it to executable: must be denied.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                exit(4); // couldn't get the setup RW page
            }
            let r = unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_EXEC) };
            if r == 0 {
                exit(3); // flip to executable succeeded: containment hole
            }
            exit(0);
        }
        _ => {
            // allowed path: a little compute, write already proven by "locked"
            let s: u64 = (0..1000u64).map(|x| x.wrapping_mul(x)).sum();
            println!("ok {s}");
        }
    }
}
