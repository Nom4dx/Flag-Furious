# Sicurezza
Sono accettati soltanto artefatti locali regolari. Niente rete, login, account o servizi remoti. I subprocess usano allowlist e `shell=False`; password redatte dagli argv di audit. Output in directory isolata, Zip Slip/symlink/archive bomb bloccati, tentativi/tempo/output limitati. Macro, script, JavaScript PDF ed eseguibili estratti restano dati passivi.
