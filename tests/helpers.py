import hashlib
import os
import threading

from lanshare import transfer


def sha(path):
    return transfer.sha256_file(path)


class Rx:
    """Запускает Receiver в потоке на свободном порту."""

    def __init__(self, out, **kw):
        kw.setdefault("quiet", True)
        kw.setdefault("advertise", False)
        kw.setdefault("host", "127.0.0.1")
        kw.setdefault("port", 0)
        kw.setdefault("auto_accept", True)
        kw.setdefault("once", True)
        self.rx = transfer.Receiver(out_dir=out, **kw)
        self.port = self.rx.listen()
        self.addr = "127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=self.rx.serve_forever, daemon=True)
        self.thread.start()

    @property
    def code(self):
        return self.rx.code

    def join(self, t=15):
        self.thread.join(t)
        assert not self.thread.is_alive(), "получатель не завершился"
        return self.rx.results

    def close(self):
        self.rx.stop()
        self.thread.join(5)


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def read(path):
    with open(path, "rb") as f:
        return f.read()
