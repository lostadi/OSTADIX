use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process::{Command, ExitCode, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use mobile_console::{
    backend::HidKeyboard,
    gadget::{GadgetState, UsbKeyboard},
    keyboard::{ascii, KeyStroke, KeyboardReport},
};

const SOCKET: &str = "/data/local/tmp/mobile-console.sock";
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn usage() {
    eprintln!("mobile-console start | stop | type <text> | key <KEY> | status\nkeys: ENTER ESC BACKSPACE TAB SPACE arrows HOME END PAGEUP PAGEDOWN DELETE F1..F12");
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn elevate() -> io::Result<i32> {
    let exe = env::current_exe()?;
    let command = env::args_os()
        .skip(1)
        .map(|a| shell_quote(&a.to_string_lossy()))
        .fold(shell_quote(&exe.to_string_lossy()), |mut out, arg| {
            out.push(' ');
            out.push_str(&arg);
            out
        });
    Command::new("su")
        .args(["-c", &command])
        .status()
        .map(|s| s.code().unwrap_or(1))
}

fn request(op: u8, payload: &[u8]) -> io::Result<String> {
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.write_all(&[op])?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    if let Some(error) = reply.strip_prefix("ERR ") {
        Err(io::Error::new(io::ErrorKind::Other, error.to_owned()))
    } else {
        Ok(reply)
    }
}

fn daemonize() -> io::Result<()> {
    if Path::new(SOCKET).exists() && request(b'S', &[]).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "mobile-console is already running",
        ));
    }
    let _ = fs::remove_file(SOCKET);
    let log = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("/data/local/tmp/mobile-console.log")?;
    let log_err = log.try_clone()?;
    Command::new(env::current_exe()?)
        .arg("__daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if let Ok(status) = request(b'S', &[]) {
            println!("{}", status.trim());
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "daemon did not start; inspect /data/local/tmp/mobile-console.log or run `su -c 'mobile-console __daemon'`"))
}

fn read_request(mut stream: &UnixStream) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    if len > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request exceeds 1 MiB",
        ));
    }
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

fn handle(stream: &mut UnixStream, keyboard: &mut UsbKeyboard, device: &Path) -> io::Result<()> {
    let (op, payload) = read_request(stream)?;
    let delay = Duration::from_millis(8);
    match op {
        b'T' => {
            let text = std::str::from_utf8(&payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "text must be UTF-8"))?;
            for c in text.chars() {
                let stroke = ascii(c).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("character {c:?} is not representable by a US keyboard"),
                    )
                })?;
                keyboard.tap(stroke, delay)?;
            }
            stream.write_all(b"OK\n")
        }
        b'K' => {
            let name = std::str::from_utf8(&payload)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key name"))?;
            let stroke: KeyStroke =
                name.parse()
                    .map_err(|e: mobile_console::keyboard::UnknownKey| {
                        io::Error::new(io::ErrorKind::InvalidInput, e)
                    })?;
            keyboard.tap(stroke, delay)?;
            stream.write_all(b"OK\n")
        }
        b'S' => stream.write_all(format!("running: {}\n", device.display()).as_bytes()),
        b'X' => {
            keyboard.send_report(KeyboardReport::released())?;
            STOP.store(true, Ordering::SeqCst);
            stream.write_all(b"stopping\n")
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown operation",
        )),
    }
}

fn daemon() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon requires root",
        ));
    }
    let state = GadgetState::configure()?;
    let mut keyboard = match UsbKeyboard::open(&state.device) {
        Ok(k) => k,
        Err(e) => {
            let _ = state.remove();
            return Err(e);
        }
    };
    let _ = fs::remove_file(SOCKET);
    let listener = match UnixListener::bind(SOCKET) {
        Ok(l) => l,
        Err(e) => {
            let _ = state.remove();
            return Err(e);
        }
    };
    fs::set_permissions(
        SOCKET,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )?;
    listener.set_nonblocking(true)?;
    unsafe {
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
    while !STOP.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(e) = handle(&mut stream, &mut keyboard, &state.device) {
                    let _ = stream.write_all(format!("ERR {e}\n").as_bytes());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(e) => {
                eprintln!("accept: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let _ = keyboard.send_report(KeyboardReport::released());
    drop(keyboard);
    drop(listener);
    let _ = fs::remove_file(SOCKET);
    state.remove()
}

fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("__daemon") {
        return daemon();
    }
    if args.is_empty() {
        usage();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }
    if unsafe { libc::geteuid() } != 0 {
        let code = elevate()?;
        if code == 0 {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("root command failed with exit status {code}"),
        ));
    }
    match args[0].as_str() {
        "start" if args.len() == 1 => daemonize(),
        "stop" if args.len() == 1 => {
            println!("{}", request(b'X', &[])?.trim());
            Ok(())
        }
        "status" if args.len() == 1 => {
            println!("{}", request(b'S', &[])?.trim());
            Ok(())
        }
        "type" if args.len() == 2 => {
            request(b'T', args[1].as_bytes())?;
            Ok(())
        }
        "key" if args.len() == 2 => {
            request(b'K', args[1].as_bytes())?;
            Ok(())
        }
        _ => {
            usage();
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid arguments",
            ))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mobile-console: {e}");
            ExitCode::FAILURE
        }
    }
}
