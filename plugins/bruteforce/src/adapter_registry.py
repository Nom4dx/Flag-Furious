"""Ordered adapter registry; specific parsers precede the generic fallback."""
from .adapters.zip_adapter import ZipAdapter
from .adapters.archive_adapter import ArchiveAdapter
from .adapters.pdf_adapter import PdfAdapter
from .adapters.office_adapter import OfficeAdapter
from .adapters.steghide_adapter import SteghideAdapter
from .adapters.openstego_adapter import OpenStegoAdapter
from .adapters.stegcloak_adapter import StegCloakAdapter
from .adapters.encrypted_text_adapter import EncryptedTextAdapter
from .adapters.generic_adapter import GenericAdapter
from .adapters.gpg_adapter import GpgAdapter
from .adapters.bitlocker_adapter import BitLockerAdapter
def adapters():
    """Return fresh stateless adapters for one isolated request."""
    return [BitLockerAdapter(),ZipAdapter(),PdfAdapter(),OfficeAdapter(),SteghideAdapter(),ArchiveAdapter(),OpenStegoAdapter(),StegCloakAdapter(),EncryptedTextAdapter(),GpgAdapter(),GenericAdapter()]
def select(artifact,context,names=None):
    """Select compatible adapters, optionally constrained by caller names."""
    return [a for a in adapters() if (not names or a.name in names) and a.can_handle(artifact,context)]
