use std::{io, time::Duration};

use crate::keyboard::{KeyStroke, KeyboardReport};

/// Transport-independent sink. A future Bluetooth backend implements this trait.
pub trait HidKeyboard {
    fn send_report(&mut self, report: KeyboardReport) -> io::Result<()>;

    fn tap(&mut self, stroke: KeyStroke, delay: Duration) -> io::Result<()> {
        self.send_report(KeyboardReport::pressed(stroke))?;
        std::thread::sleep(delay);
        self.send_report(KeyboardReport::released())?;
        std::thread::sleep(delay);
        Ok(())
    }
}
