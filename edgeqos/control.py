"""Same-origin, designated-admin access and serialized runtime mode requests."""
import secrets
import threading


class ModeControl:
    def __init__(self, config):
        self.allowed=set(config.get('control_clients', ['127.0.0.1']))
        self.token=secrets.token_urlsafe(32)
        self.lock=threading.Lock()
        self.pending=None
        self.busy=False
        self.error=None

    def authorized(self, peer, host, local, origin=None, fetch_site=None):
        # Numeric Host validation also prevents DNS-rebinding pages from reading
        # the token. Requests through a proxy/hostname are intentionally denied.
        if peer not in self.allowed or host!=f'{local[0]}:{local[1]}': return False
        if fetch_site=='cross-site': return False
        return origin is None or origin==f'http://{host}'

    def valid_token(self, value):
        return secrets.compare_digest(value or '', self.token)

    def request(self, enabled):
        if type(enabled) is not bool: raise ValueError('ai_enabled must be true or false')
        with self.lock:
            if self.busy: raise RuntimeError('A mode change is already being applied')
            self.pending=enabled; self.busy=True; self.error=None

    def take(self):
        with self.lock:
            pending=self.pending; self.pending=None
            return pending

    def finish(self, error=None):
        with self.lock:
            self.busy=False; self.error=error

    def state(self, mode):
        with self.lock:
            return dict(ai_enabled=mode=='enforce',pending=self.busy,
                        error=self.error,restart_mode='normal')
