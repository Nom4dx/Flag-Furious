"""Password normalization that preserves meaningful spaces by default."""
import unicodedata
def normalize(value:str,strip_spaces:bool=False)->str:
    """Normalize NFC and line endings; strip only the wordlist newline."""
    value=value.rstrip("\r\n")
    return unicodedata.normalize("NFC",value.strip() if strip_spaces else value)
