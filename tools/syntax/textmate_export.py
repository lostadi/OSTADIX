"""Preserve regex characters that XML 1.0 cannot represent in a tmLanguage file."""

import re

NON_XML = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def xml_safe(value):
    """Represent forbidden literal regex characters with equivalent Oniguruma escapes."""
    if isinstance(value, str):
        return NON_XML.sub(lambda match: r"\x{%X}" % ord(match[0]), value)
    if isinstance(value, list):
        return [xml_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: xml_safe(item) for key, item in value.items()}
    return value
