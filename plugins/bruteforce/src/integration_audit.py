"""Machine-readable audit of existing password-capable plugins."""
AUDIT=[
 {'plugin':'archive-extractor','files':['plugin.py'],'formats':['zip'],'protection':'zipcrypto/zip_aes','adapter':'zip_adapter','integration_completed':True,'tests':['test_integrations.py']},
 {'plugin':'polyglot-and-embedded-content','files':['src/archive_analyzer.py','src/validators.py'],'formats':['zip','7z','rar'],'protection':'archive password','adapter':'zip_adapter/archive_adapter','integration_completed':True,'tests':['test_integrations.py']},
 {'plugin':'seganografy','files':['src/container_extract.py','src/external_tools.py'],'formats':['zip','jpeg','bmp','wav','au'],'protection':'zip/steghide','adapter':'zip_adapter/steghide_adapter','integration_completed':True,'tests':['test_integrations.py']},
 {'plugin':'ext4atto','files':['src/backend/diskhunt/extraction.py'],'formats':['7z','rar'],'protection':'archive password','adapter':'archive_adapter','integration_completed':True,'tests':['test_integrations.py']},
 {'plugin':'encrypted-volume-forensics','files':['plugin.py','src/bruteforce_bridge.py'],'formats':['BitLocker/FVE'],'protection':'password/recovery password','adapter':'bitlocker_adapter','integration_completed':True,'tests':['test_bitlocker_adapter.py']},
]
def report():
    """Return a copy suitable for JSON reports."""
    return {'plugins_audited':['archive-extractor','document-metadata-forensics','ext4atto','githappens','hidgrabber','pic-up','polyglot-and-embedded-content','seganografy','text-inspector'],'plugins_requiring_password':[x['plugin'] for x in AUDIT],'plugins_already_supporting_password':['seganografy'],'plugins_requiring_integration':[],'unsupported_cases':['network authentication','unknown proprietary encryption'],'integration_status':AUDIT}
