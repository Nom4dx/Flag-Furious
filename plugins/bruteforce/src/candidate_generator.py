"""Bounded optional candidate transformations, disabled by default."""
from datetime import datetime,timezone
import hashlib
from .candidate_normalizer import normalize
def variants(value:str,enabled:bool=False,year:int|None=None):
    """Yield deterministic unique variants; never logs raw values."""
    base=normalize(value); values=[base]
    if enabled:
        year=datetime.now(timezone.utc).year if year is None else int(year); clean=''.join(c for c in base if c.isalnum() or c.isspace())
        values += [base.lower(),base.upper(),base.capitalize(),base[::-1],base.replace(' ',''),clean,base.translate(str.maketrans('aAeEiIoOsS','4433110055')),f'{base}{year}',f'{base}{year-1}',f'{base}1',f'1{base}']
    seen=set()
    for item in values:
        digest=hashlib.sha256(item.encode()).hexdigest()
        if digest not in seen:seen.add(digest);yield item
