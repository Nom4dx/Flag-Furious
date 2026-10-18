from __future__ import annotations


MODIFIERS = {
    0x01: "LEFT_CTRL",
    0x02: "LEFT_SHIFT",
    0x04: "LEFT_ALT",
    0x08: "LEFT_GUI",
    0x10: "RIGHT_CTRL",
    0x20: "RIGHT_SHIFT",
    0x40: "RIGHT_ALT",
    0x80: "RIGHT_GUI",
}


USAGE_NAMES = {value: f"RESERVED_0x{value:02X}" for value in range(256)}
USAGE_NAMES.update({
    0x00: "NO_EVENT", 0x01: "ERROR_ROLLOVER", 0x02: "POST_FAIL", 0x03: "ERROR_UNDEFINED",
    0x28: "ENTER", 0x29: "ESCAPE", 0x2A: "BACKSPACE", 0x2B: "TAB", 0x2C: "SPACE",
    0x2D: "MINUS", 0x2E: "EQUAL", 0x2F: "LEFT_BRACKET", 0x30: "RIGHT_BRACKET",
    0x31: "BACKSLASH", 0x32: "NON_US_HASH", 0x33: "SEMICOLON", 0x34: "APOSTROPHE",
    0x35: "GRAVE", 0x36: "COMMA", 0x37: "PERIOD", 0x38: "SLASH",
    0x39: "CAPS_LOCK", 0x3A: "F1", 0x3B: "F2", 0x3C: "F3", 0x3D: "F4",
    0x3E: "F5", 0x3F: "F6", 0x40: "F7", 0x41: "F8", 0x42: "F9", 0x43: "F10",
    0x44: "F11", 0x45: "F12", 0x46: "PRINT_SCREEN", 0x47: "SCROLL_LOCK",
    0x48: "PAUSE", 0x49: "INSERT", 0x4A: "HOME", 0x4B: "PAGE_UP", 0x4C: "DELETE",
    0x4D: "END", 0x4E: "PAGE_DOWN", 0x4F: "RIGHT", 0x50: "LEFT", 0x51: "DOWN",
    0x52: "UP", 0x53: "NUM_LOCK", 0x54: "KEYPAD_SLASH", 0x55: "KEYPAD_ASTERISK",
    0x56: "KEYPAD_MINUS", 0x57: "KEYPAD_PLUS", 0x58: "KEYPAD_ENTER",
    0x59: "KEYPAD_1", 0x5A: "KEYPAD_2", 0x5B: "KEYPAD_3", 0x5C: "KEYPAD_4",
    0x5D: "KEYPAD_5", 0x5E: "KEYPAD_6", 0x5F: "KEYPAD_7", 0x60: "KEYPAD_8",
    0x61: "KEYPAD_9", 0x62: "KEYPAD_0", 0x63: "KEYPAD_DECIMAL",
    0x64: "NON_US_BACKSLASH", 0x65: "APPLICATION", 0x66: "POWER", 0x67: "KEYPAD_EQUAL",
    0x68: "F13", 0x69: "F14", 0x6A: "F15", 0x6B: "F16", 0x6C: "F17", 0x6D: "F18",
    0x6E: "F19", 0x6F: "F20", 0x70: "F21", 0x71: "F22", 0x72: "F23", 0x73: "F24",
    0x74: "EXECUTE", 0x75: "HELP", 0x76: "MENU", 0x77: "SELECT", 0x78: "STOP",
    0x79: "AGAIN", 0x7A: "UNDO", 0x7B: "CUT", 0x7C: "COPY", 0x7D: "PASTE",
    0x7E: "FIND", 0x7F: "MUTE", 0x80: "VOLUME_UP", 0x81: "VOLUME_DOWN",
    0x82: "LOCKING_CAPS_LOCK", 0x83: "LOCKING_NUM_LOCK", 0x84: "LOCKING_SCROLL_LOCK",
    0x85: "KEYPAD_COMMA", 0x86: "KEYPAD_EQUAL_SIGN", 0x99: "ALTERNATE_ERASE",
    0x9A: "SYSREQ", 0x9B: "CANCEL", 0x9C: "CLEAR", 0x9D: "PRIOR", 0x9E: "RETURN",
    0x9F: "SEPARATOR", 0xA0: "OUT", 0xA1: "OPER", 0xA2: "CLEAR_AGAIN",
    0xA3: "CRSEL", 0xA4: "EXSEL", 0xB0: "KEYPAD_00", 0xB1: "KEYPAD_000",
    0xB2: "THOUSANDS_SEPARATOR", 0xB3: "DECIMAL_SEPARATOR", 0xB4: "CURRENCY_UNIT",
    0xB5: "CURRENCY_SUBUNIT", 0xB6: "KEYPAD_LEFT_PAREN", 0xB7: "KEYPAD_RIGHT_PAREN",
    0xB8: "KEYPAD_LEFT_BRACE", 0xB9: "KEYPAD_RIGHT_BRACE", 0xBA: "KEYPAD_TAB",
    0xBB: "KEYPAD_BACKSPACE", 0xBC: "KEYPAD_A", 0xBD: "KEYPAD_B", 0xBE: "KEYPAD_C",
    0xBF: "KEYPAD_D", 0xC0: "KEYPAD_E", 0xC1: "KEYPAD_F", 0xC2: "KEYPAD_XOR",
    0xC3: "KEYPAD_CARET", 0xC4: "KEYPAD_PERCENT", 0xC5: "KEYPAD_LESS",
    0xC6: "KEYPAD_GREATER", 0xC7: "KEYPAD_AMPERSAND", 0xC8: "KEYPAD_DOUBLE_AMPERSAND",
    0xC9: "KEYPAD_PIPE", 0xCA: "KEYPAD_DOUBLE_PIPE", 0xCB: "KEYPAD_COLON",
    0xCC: "KEYPAD_HASH", 0xCD: "KEYPAD_SPACE", 0xCE: "KEYPAD_AT", 0xCF: "KEYPAD_EXCLAMATION",
    0xD0: "KEYPAD_MEMORY_STORE", 0xD1: "KEYPAD_MEMORY_RECALL", 0xD2: "KEYPAD_MEMORY_CLEAR",
    0xD3: "KEYPAD_MEMORY_ADD", 0xD4: "KEYPAD_MEMORY_SUBTRACT", 0xD5: "KEYPAD_MEMORY_MULTIPLY",
    0xD6: "KEYPAD_MEMORY_DIVIDE", 0xD7: "KEYPAD_PLUS_MINUS", 0xD8: "KEYPAD_CLEAR",
    0xD9: "KEYPAD_CLEAR_ENTRY", 0xDA: "KEYPAD_BINARY", 0xDB: "KEYPAD_OCTAL",
    0xDC: "KEYPAD_DECIMAL_MODE", 0xDD: "KEYPAD_HEXADECIMAL",
    0xE0: "LEFT_CTRL", 0xE1: "LEFT_SHIFT", 0xE2: "LEFT_ALT", 0xE3: "LEFT_GUI",
    0xE4: "RIGHT_CTRL", 0xE5: "RIGHT_SHIFT", 0xE6: "RIGHT_ALT", 0xE7: "RIGHT_GUI",
})

for offset, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ", start=0x04):
    USAGE_NAMES[offset] = letter
for offset, digit in enumerate("1234567890", start=0x1E):
    USAGE_NAMES[offset] = digit
for offset in range(9):
    USAGE_NAMES[0x87 + offset] = f"INTERNATIONAL_{offset + 1}"
    USAGE_NAMES[0x90 + offset] = f"LANG_{offset + 1}"


SPECIAL_ACTIONS = {
    0x28: "\n", 0x29: "[ESC]", 0x2A: "[BACKSPACE]", 0x2B: "\t", 0x2C: " ",
    0x46: "[PRINT_SCREEN]", 0x47: "[SCROLL_LOCK]", 0x48: "[PAUSE]",
    0x49: "[INSERT]", 0x4A: "[HOME]", 0x4B: "[PAGE_UP]", 0x4C: "[DELETE]",
    0x4D: "[END]", 0x4E: "[PAGE_DOWN]", 0x4F: "[RIGHT]", 0x50: "[LEFT]",
    0x51: "[DOWN]", 0x52: "[UP]", 0x58: "\n", 0x65: "[MENU]",
}


def _letters() -> dict[int, tuple[str, str]]:
    return {code: (letter, letter.upper()) for code, letter in enumerate("abcdefghijklmnopqrstuvwxyz", 0x04)}


US_LAYOUT = _letters()
US_LAYOUT.update({
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"), 0x2D: ("-", "_"), 0x2E: ("=", "+"),
    0x2F: ("[", "{"), 0x30: ("]", "}"), 0x31: ("\\", "|"), 0x32: ("#", "~"),
    0x33: (";", ":"), 0x34: ("'", '"'), 0x35: ("`", "~"), 0x36: (",", "<"),
    0x37: (".", ">"), 0x38: ("/", "?"), 0x64: ("\\", "|"),
})


UK_LAYOUT = dict(US_LAYOUT)
UK_LAYOUT.update({
    0x1F: ("2", '"'), 0x20: ("3", "£"), 0x31: ("#", "~"),
    0x34: ("'", "@"), 0x35: ("`", "¬"), 0x64: ("\\", "|"),
})


IT_LAYOUT = _letters()
IT_LAYOUT.update({
    0x1E: ("1", "!"), 0x1F: ("2", '"'), 0x20: ("3", "£"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "&"), 0x24: ("7", "/"), 0x25: ("8", "("),
    0x26: ("9", ")"), 0x27: ("0", "="), 0x2D: ("'", "?"), 0x2E: ("ì", "^"),
    0x2F: ("è", "é"), 0x30: ("+", "]"), 0x31: ("ù", "§"), 0x32: ("\\", "|"),
    0x33: ("ò", "ç"), 0x34: ("à", "°"), 0x35: ("\\", "|"), 0x36: (",", ";"),
    0x37: (".", ":"), 0x38: ("-", "_"), 0x64: ("<", ">"),
})


IT_ALTGR = {
    0x08: "€", 0x1F: "@", 0x20: "#", 0x2F: "[", 0x30: "]",
    0x31: "\\", 0x33: "@", 0x34: "#",
}


LAYOUTS = {
    "us": {"keys": US_LAYOUT, "altgr": {}},
    "uk": {"keys": UK_LAYOUT, "altgr": {}},
    "it": {"keys": IT_LAYOUT, "altgr": IT_ALTGR},
}


KEYPAD_DIGITS = {
    0x59: "1", 0x5A: "2", 0x5B: "3", 0x5C: "4", 0x5D: "5",
    0x5E: "6", 0x5F: "7", 0x60: "8", 0x61: "9", 0x62: "0",
}


KEYPAD_TEXT = {
    **KEYPAD_DIGITS,
    0x54: "/", 0x55: "*", 0x56: "-", 0x57: "+", 0x63: ".", 0x67: "=",
}
