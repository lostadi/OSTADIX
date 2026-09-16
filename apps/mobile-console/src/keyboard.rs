use std::{fmt, str::FromStr};

pub const MOD_LEFT_CTRL: u8 = 0x01;
pub const MOD_LEFT_SHIFT: u8 = 0x02;
pub const MOD_LEFT_ALT: u8 = 0x04;
pub const MOD_LEFT_GUI: u8 = 0x08;

/// Standard boot-keyboard descriptor: modifiers, reserved byte, six key slots.
pub const REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08,
    0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyStroke {
    pub pub_modifier: u8,
    pub usage: u8,
}

impl KeyStroke {
    pub const fn new(modifier: u8, usage: u8) -> Self {
        Self {
            pub_modifier: modifier,
            usage,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardReport(pub [u8; 8]);

impl KeyboardReport {
    pub fn pressed(k: KeyStroke) -> Self {
        Self([k.pub_modifier, 0, k.usage, 0, 0, 0, 0, 0])
    }
    pub const fn released() -> Self {
        Self([0; 8])
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnknownKey(pub String);
impl fmt::Display for UnknownKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown key: {}", self.0)
    }
}
impl std::error::Error for UnknownKey {}

pub fn ascii(c: char) -> Option<KeyStroke> {
    let shift = MOD_LEFT_SHIFT;
    Some(match c {
        'a'..='z' => KeyStroke::new(0, 0x04 + (c as u8 - b'a')),
        'A'..='Z' => KeyStroke::new(shift, 0x04 + (c as u8 - b'A')),
        '1'..='9' => KeyStroke::new(0, 0x1e + (c as u8 - b'1')),
        '0' => KeyStroke::new(0, 0x27),
        '\n' | '\r' => KeyStroke::new(0, 0x28),
        '\x1b' => KeyStroke::new(0, 0x29),
        '\x08' => KeyStroke::new(0, 0x2a),
        '\t' => KeyStroke::new(0, 0x2b),
        ' ' => KeyStroke::new(0, 0x2c),
        '-' => KeyStroke::new(0, 0x2d),
        '_' => KeyStroke::new(shift, 0x2d),
        '=' => KeyStroke::new(0, 0x2e),
        '+' => KeyStroke::new(shift, 0x2e),
        '[' => KeyStroke::new(0, 0x2f),
        '{' => KeyStroke::new(shift, 0x2f),
        ']' => KeyStroke::new(0, 0x30),
        '}' => KeyStroke::new(shift, 0x30),
        '\\' => KeyStroke::new(0, 0x31),
        '|' => KeyStroke::new(shift, 0x31),
        ';' => KeyStroke::new(0, 0x33),
        ':' => KeyStroke::new(shift, 0x33),
        '\'' => KeyStroke::new(0, 0x34),
        '"' => KeyStroke::new(shift, 0x34),
        '`' => KeyStroke::new(0, 0x35),
        '~' => KeyStroke::new(shift, 0x35),
        ',' => KeyStroke::new(0, 0x36),
        '<' => KeyStroke::new(shift, 0x36),
        '.' => KeyStroke::new(0, 0x37),
        '>' => KeyStroke::new(shift, 0x37),
        '/' => KeyStroke::new(0, 0x38),
        '?' => KeyStroke::new(shift, 0x38),
        '!' => KeyStroke::new(shift, 0x1e),
        '@' => KeyStroke::new(shift, 0x1f),
        '#' => KeyStroke::new(shift, 0x20),
        '$' => KeyStroke::new(shift, 0x21),
        '%' => KeyStroke::new(shift, 0x22),
        '^' => KeyStroke::new(shift, 0x23),
        '&' => KeyStroke::new(shift, 0x24),
        '*' => KeyStroke::new(shift, 0x25),
        '(' => KeyStroke::new(shift, 0x26),
        ')' => KeyStroke::new(shift, 0x27),
        _ => return None,
    })
}

impl FromStr for KeyStroke {
    type Err = UnknownKey;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let upper = value.to_ascii_uppercase();
        let usage = match upper.as_str() {
            "ENTER" | "RETURN" => 0x28,
            "ESC" | "ESCAPE" => 0x29,
            "BACKSPACE" => 0x2a,
            "TAB" => 0x2b,
            "SPACE" => 0x2c,
            "CAPSLOCK" => 0x39,
            "RIGHT" => 0x4f,
            "LEFT" => 0x50,
            "DOWN" => 0x51,
            "UP" => 0x52,
            "HOME" => 0x4a,
            "PAGEUP" => 0x4b,
            "DELETE" => 0x4c,
            "END" => 0x4d,
            "PAGEDOWN" => 0x4e,
            _ if upper.starts_with('F') => upper[1..]
                .parse::<u8>()
                .ok()
                .filter(|n| (1..=12).contains(n))
                .map(|n| 0x3a + n - 1)
                .ok_or_else(|| UnknownKey(value.into()))?,
            _ if value.chars().count() == 1 => {
                return ascii(value.chars().next().unwrap()).ok_or_else(|| UnknownKey(value.into()))
            }
            _ => return Err(UnknownKey(value.into())),
        };
        Ok(KeyStroke::new(0, usage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_and_report_are_boot_keyboard_sized() {
        assert_eq!(REPORT_DESCRIPTOR.len(), 45);
        assert_eq!(KeyboardReport::released().0.len(), 8);
    }
    #[test]
    fn ascii_shift_mapping() {
        assert_eq!(ascii('a'), Some(KeyStroke::new(0, 4)));
        assert_eq!(ascii('A'), Some(KeyStroke::new(2, 4)));
        assert_eq!(ascii('?'), Some(KeyStroke::new(2, 0x38)));
    }
    #[test]
    fn named_keys() {
        assert_eq!("ENTER".parse(), Ok(KeyStroke::new(0, 0x28)));
        assert_eq!("F12".parse(), Ok(KeyStroke::new(0, 0x45)));
    }
}
