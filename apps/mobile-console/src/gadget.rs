use std::{
    fs,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::fs::{symlink, MetadataExt},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use crate::{
    backend::HidKeyboard,
    keyboard::{KeyboardReport, REPORT_DESCRIPTOR},
};

const ROOT: &str = "/config/usb_gadget";
const OWN_GADGET: &str = "mobile_console";
const FUNCTION: &str = "hid.mobile_console";

#[derive(Debug)]
pub struct GadgetState {
    pub gadget: PathBuf,
    pub config: PathBuf,
    pub function: PathBuf,
    pub link: PathBuf,
    pub udc: String,
    pub owned_gadget: bool,
    pub device: PathBuf,
}

fn write(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path, data)
}

fn first_dir(path: &Path) -> io::Result<Option<PathBuf>> {
    Ok(fs::read_dir(path)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir()))
}

fn active_gadget() -> io::Result<Option<(PathBuf, String)>> {
    let root = Path::new(ROOT);
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "USB configfs is not mounted at /config/usb_gadget",
        ));
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let udc = fs::read_to_string(path.join("UDC"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !udc.is_empty() {
            return Ok(Some((path, udc)));
        }
    }
    Ok(None)
}

fn only_udc() -> io::Result<String> {
    let names: Vec<_> = fs::read_dir("/sys/class/udc")?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    match names.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no USB Device Controller found",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple UDCs found; cannot choose safely",
        )),
    }
}

fn create_owned() -> io::Result<(PathBuf, PathBuf, String)> {
    let gadget = Path::new(ROOT).join(OWN_GADGET);
    fs::create_dir(&gadget)?;
    write(gadget.join("idVendor"), "0x18d1")?;
    write(gadget.join("idProduct"), "0x4ee7")?;
    write(gadget.join("bcdDevice"), "0x0100")?;
    write(gadget.join("bcdUSB"), "0x0200")?;
    let strings = gadget.join("strings/0x409");
    fs::create_dir_all(&strings)?;
    write(strings.join("serialnumber"), "mobile-console")?;
    write(strings.join("manufacturer"), "Ostadix")?;
    write(strings.join("product"), "Mobile Console Keyboard")?;
    let config = gadget.join("configs/c.1");
    fs::create_dir_all(config.join("strings/0x409"))?;
    write(config.join("strings/0x409/configuration"), "HID keyboard")?;
    write(config.join("MaxPower"), "250")?;
    Ok((gadget, config, only_udc()?))
}

fn function_device(function: &Path) -> Option<(u64, u64)> {
    let value = fs::read_to_string(function.join("dev")).ok()?;
    let (major, minor) = value.trim().split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn find_hidg(function: &Path, before: &[PathBuf]) -> io::Result<PathBuf> {
    for _ in 0..50 {
        let mut candidates = Vec::new();
        if let Ok(entries) = fs::read_dir("/dev") {
            candidates.extend(
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("hidg"))
                    }),
            );
        }
        let expected = function_device(function);
        if let Some(path) = candidates.iter().find(|path| {
            if let (Some((major, minor)), Ok(meta)) = (expected, fs::metadata(path)) {
                libc::major(meta.rdev()) as u64 == major && libc::minor(meta.rdev()) as u64 == minor
            } else {
                !before.contains(path)
            }
        }) {
            return Ok(path.clone());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "kernel did not create /dev/hidgN (check ueventd/SELinux policy)",
    ))
}

fn hidg_devices() -> Vec<PathBuf> {
    fs::read_dir("/dev")
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("hidg"))
        })
        .collect()
}

impl GadgetState {
    /// Add HID to Android's active composite gadget when possible; otherwise create an owned gadget.
    pub fn configure() -> io::Result<Self> {
        let before = hidg_devices();
        let active = active_gadget()?;
        let owned_gadget = active.is_none();
        let (gadget, config, udc) = if let Some((g, u)) = active {
            let config = first_dir(&g.join("configs"))?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "active gadget has no configuration",
                )
            })?;
            (g, config, u)
        } else {
            create_owned()?
        };

        // Functions/configuration links may only be changed while unbound.
        write(gadget.join("UDC"), "")?;
        let function = gadget.join("functions").join(FUNCTION);
        let link = config.join(FUNCTION);
        let result = (|| {
            fs::create_dir(&function)?;
            write(function.join("protocol"), "1")?;
            write(function.join("subclass"), "1")?;
            write(function.join("report_length"), "8")?;
            write(function.join("report_desc"), REPORT_DESCRIPTOR)?;
            symlink(&function, &link)?;
            write(gadget.join("UDC"), &udc)?;
            let device = find_hidg(&function, &before)?;
            Ok(Self {
                gadget: gadget.clone(),
                config: config.clone(),
                function: function.clone(),
                link: link.clone(),
                udc: udc.clone(),
                owned_gadget,
                device,
            })
        })();
        if result.is_err() {
            let _ = write(gadget.join("UDC"), "");
            if link.exists() {
                let _ = fs::remove_file(&link);
            }
            if function.exists() {
                let _ = fs::remove_dir(&function);
            }
            if owned_gadget {
                let _ = fs::remove_dir(config.join("strings/0x409"));
                let _ = fs::remove_dir(&config);
                let _ = fs::remove_dir(gadget.join("strings/0x409"));
                let _ = fs::remove_dir(&gadget);
            } else {
                let _ = write(gadget.join("UDC"), &udc);
            }
        }
        result
    }

    pub fn remove(&self) -> io::Result<()> {
        write(self.gadget.join("UDC"), "")?;
        if self.link.exists() {
            fs::remove_file(&self.link)?;
        }
        if self.function.exists() {
            fs::remove_dir(&self.function)?;
        }
        if self.owned_gadget {
            let _ = fs::remove_dir(self.config.join("strings/0x409"));
            let _ = fs::remove_dir(&self.config);
            let _ = fs::remove_dir(self.gadget.join("strings/0x409"));
            fs::remove_dir(&self.gadget)?;
        } else {
            write(self.gadget.join("UDC"), &self.udc)?;
        }
        Ok(())
    }
}

pub struct UsbKeyboard {
    file: fs::File,
}
impl UsbKeyboard {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: OpenOptions::new().write(true).open(path)?,
        })
    }
}
impl HidKeyboard for UsbKeyboard {
    fn send_report(&mut self, report: KeyboardReport) -> io::Result<()> {
        self.file.write_all(&report.0).or_else(|e| {
            if matches!(
                e.raw_os_error(),
                Some(libc::ENODEV | libc::ESHUTDOWN | libc::EPIPE)
            ) {
                Err(io::Error::new(io::ErrorKind::NotConnected, e))
            } else {
                Err(e)
            }
        })
    }
}
