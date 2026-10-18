"""Thread-safe pause/cancel progress state used by broker sessions."""
import threading,time
class Progress:
    """Mutable runtime state; secrets are never stored here."""
    def __init__(self):self.status='queued';self.attempts=0;self.started=None;self.current_wordlist='';self.last_index=0;self._pause=threading.Event();self._cancel=threading.Event()
    def start(self):self.status='running';self.started=time.monotonic()
    def pause(self):self.status='paused';self._pause.set()
    def resume(self):self.status='running';self._pause.clear()
    def cancel(self):self.status='cancelled';self._cancel.set()
    def checkpoint(self):
        while self._pause.is_set() and not self._cancel.is_set():time.sleep(.05)
        return not self._cancel.is_set()
    def public(self):
        elapsed=max(.001,time.monotonic()-(self.started or time.monotonic()));return {'status':self.status,'attempts':self.attempts,'last_index':self.last_index,'active_wordlist':self.current_wordlist,'elapsed':round(elapsed,3),'attempts_per_second':round(self.attempts/elapsed,2)}
