"""Передача файлов и папок: рукопожатие, манифест, подтверждение, докачка."""
import hashlib
import hmac
import os
import secrets
import socket
import sys
import threading
import time

from . import discovery
from .crypto import (AuthError, ProtocolError, SecureChannel, Spake2,
                     normalize_code, recv_plain, send_plain)

CHUNK = 256 * 1024
MAX_FILES = 100_000

_WORDS = (
    "apple river stone cloud tiger maple piano orbit lemon cedar amber coral "
    "delta ember frost grape honey ivory jelly kiwi lunar mango noble ocean "
    "pearl quartz raven solar tulip umbra velvet willow xenon yacht zebra "
    "anchor bridge candle dragon engine forest garden harbor island jungle "
    "kettle ladder meadow needle orchid pebble rocket saddle timber valley "
    "walnut yellow breeze comet dune echo flame glacier haze iris jade koala "
    "lotus mist nova olive prism quill reef spark thunder vapor wave"
).split()


def make_code() -> str:
    return "%d-%s-%s" % (10 + secrets.randbelow(90), secrets.choice(_WORDS), secrets.choice(_WORDS))


class Declined(Exception):
    """Получатель отказался принимать файлы."""


# ------------------------------------------------------------------ helpers
def human(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return "%d %s" % (n, unit) if unit == "Б" else "%.1f %s" % (n, unit)
        n /= 1024


class Progress:
    def __init__(self, total, label, quiet=False):
        self.total, self.label, self.quiet = total, label, quiet
        self.done = 0
        self.start = time.monotonic()
        self._last = 0.0
        self._tty = sys.stderr.isatty()

    def update(self, n):
        self.done += n
        if self.quiet:
            return
        now = time.monotonic()
        if now - self._last < 0.1 and self.done < self.total:
            return
        self._last = now
        if not self._tty:
            return
        frac = self.done / self.total if self.total else 1.0
        bar = "#" * int(frac * 30)
        speed = self.done / max(now - self.start, 1e-6)
        sys.stderr.write("\r%s [%-30s] %3d%%  %s/%s  %s/с " % (
            self.label, bar, frac * 100, human(self.done), human(self.total), human(speed)))
        sys.stderr.flush()

    def finish(self):
        if not self.quiet and self._tty:
            sys.stderr.write("\n")
        if not self.quiet and not self._tty:
            print("%s: %s за %.1f с" % (self.label, human(self.done), time.monotonic() - self.start))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def collect(paths):
    """[(абсолютный путь, относительный posix-путь)]. Симлинки пропускаются."""
    items = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.islink(p):
            continue
        if os.path.isfile(p):
            items.append((p, os.path.basename(p)))
        elif os.path.isdir(p):
            base = os.path.basename(p.rstrip(os.sep)) or "folder"
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    if os.path.islink(full) or not os.path.isfile(full):
                        continue
                    rel = os.path.relpath(full, p).replace(os.sep, "/")
                    items.append((full, base + "/" + rel))
        else:
            raise FileNotFoundError(p)
    seen = set()
    for _, rel in items:
        if rel in seen:
            raise ValueError("два файла с одинаковым именем в передаче: " + rel)
        seen.add(rel)
    if not items:
        raise ValueError("нечего отправлять")
    if len(items) > MAX_FILES:
        raise ValueError("слишком много файлов (максимум %d)" % MAX_FILES)
    return items


def safe_parts(rel):
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel or ":" in rel:
        raise ProtocolError("недопустимый путь в манифесте")
    parts = rel.split("/")
    if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ProtocolError("недопустимый путь в манифесте: " + rel)
    return parts


def _unique(path):
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while os.path.exists("%s (%d)%s" % (root, i, ext)):
        i += 1
    return "%s (%d)%s" % (root, i, ext)


# ------------------------------------------------------------ client side
def client_handshake(sock, code):
    """Рукопожатие отправителя. Возвращает (SecureChannel, имя получателя)."""
    sp = Spake2("A", code)
    send_plain(sock, {"v": 1, "X": "%x" % sp.msg})
    try:
        reply = recv_plain(sock)
        keys = sp.finish(int(reply["Y"], 16))
        send_plain(sock, {"mac": keys.my_confirm.hex()})
        theirs = recv_plain(sock)
    except (ConnectionError, ValueError, KeyError, TypeError) as e:
        if isinstance(e, ConnectionError):
            raise AuthError("неверный код сопряжения (или получатель закрыл соединение)")
        raise ProtocolError("некорректный ответ получателя")
    try:
        their_mac = bytes.fromhex(str(theirs.get("mac", "")))
    except ValueError:
        their_mac = b""
    if not hmac.compare_digest(their_mac, keys.peer_confirm):
        raise AuthError("получатель не подтвердил код сопряжения")
    return SecureChannel(sock, keys), str(reply.get("name", "?"))


def send(addr, paths, code, name=None, quiet=True, tag=""):
    """Отправляет файлы/папки получателю addr="host:port". Возвращает список результатов."""
    host, sep, port_s = addr.rpartition(":")
    if not sep or not host or not port_s.isdigit():
        raise ValueError("адрес должен быть в формате host:port")
    items = collect(paths)
    if not quiet:
        print("%sСчитаю контрольные суммы (%d файл(ов))..." % (tag, len(items)))
    manifest = []
    for full, rel in items:
        manifest.append({"path": rel, "size": os.path.getsize(full), "sha256": sha256_file(full)})
    total = sum(m["size"] for m in manifest)

    with socket.create_connection((host, int(port_s)), timeout=5) as sock:
        sock.settimeout(60)
        chan, peer = client_handshake(sock, code)
        if not quiet:
            print("%sСопряжено с «%s», жду подтверждения..." % (tag, peer))
        sock.settimeout(None)
        chan.send_obj({"type": "manifest", "sender": name or socket.gethostname(), "files": manifest})
        resp = chan.recv_obj()
        if not resp.get("accept"):
            raise Declined("получатель «%s» отказался принять файлы" % peer)
        offsets = resp.get("offsets", [])
        skips = resp.get("skip", [])
        if len(offsets) != len(manifest) or len(skips) != len(manifest):
            raise ProtocolError("некорректный ответ получателя")

        todo = sum(m["size"] - o for m, o, s in zip(manifest, offsets, skips) if not s)
        prog = Progress(todo, tag + "Отправка", quiet)
        for (full, _), m, off, skip in zip(items, manifest, offsets, skips):
            if skip:
                continue
            if not (0 <= off <= m["size"]):
                raise ProtocolError("некорректное смещение докачки")
            with open(full, "rb") as f:
                f.seek(off)
                left = m["size"] - off
                while left > 0:
                    data = f.read(min(CHUNK, left))
                    if not data:
                        raise IOError("файл изменился во время отправки: " + full)
                    chan.send_frame(data)
                    left -= len(data)
                    prog.update(len(data))
        prog.finish()
        done = chan.recv_obj()
    results = done.get("results", [])
    for r in results:
        if not r.get("ok"):
            raise ProtocolError("файл %s не прошёл проверку у получателя" % r.get("path"))
    return results


# ------------------------------------------------------------ server side
class Receiver:
    def __init__(self, out_dir=".", name=None, port=9000, code=None, auto_accept=False,
                 once=False, ask=None, quiet=False, host="0.0.0.0", advertise=True,
                 discovery_kwargs=None, max_failures=3):
        self.out_dir = os.path.abspath(out_dir)
        self.name = name or socket.gethostname()
        self.port = port
        self.code = normalize_code(code) if code else make_code()
        self.auto_accept = auto_accept
        self.once = once
        self.ask = ask or self._ask_stdin
        self.quiet = quiet
        self.host = host
        self.advertise = advertise
        self.discovery_kwargs = discovery_kwargs or {}
        self.max_failures = max_failures
        self.failures = 0
        self.results = []          # результаты завершённых сессий
        self._srv = None
        self._adv = None
        self._stop = threading.Event()
        self._paired = False

    def log(self, *a):
        if not self.quiet:
            print(*a)

    @staticmethod
    def _ask_stdin(text):
        try:
            return input(text + " [y/N] ").strip().lower() in ("y", "yes", "д", "да")
        except EOFError:
            return False

    def listen(self):
        os.makedirs(self.out_dir, exist_ok=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        s.settimeout(0.5)
        self._srv = s
        self.port = s.getsockname()[1]
        if self.advertise:
            self._adv = discovery.Advertiser(self.name, self.port, **self.discovery_kwargs)
            self._adv.start()
            if self._adv.error:
                self.log("Предупреждение: обнаружение отключено (%s)" % self._adv.error)
        return self.port

    def stop(self):
        self._stop.set()

    def serve_forever(self):
        if self._srv is None:
            self.listen()
        self.log("Получатель «%s» слушает порт %d" % (self.name, self.port))
        self.log("Код сопряжения: %s" % self.code)
        try:
            while not self._stop.is_set():
                try:
                    conn, addr = self._srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    self._paired = False
                    try:
                        authed = self._session(conn, addr)
                    except AuthError as e:
                        self._auth_failed(addr, str(e))
                        continue
                    except (ConnectionError, ProtocolError, socket.timeout, OSError) as e:
                        self.log("Сессия с %s прервана: %s" % (addr[0], e))
                        authed = self._paired
                if authed and self.once:
                    break
        finally:
            if self._adv:
                self._adv.stop()
            self._srv.close()

    def _auth_failed(self, addr, why):
        self.failures += 1
        self.log("Неудачная попытка сопряжения с %s (%s) [%d/%d]" % (addr[0], why, self.failures, self.max_failures))
        if self.failures >= self.max_failures:
            self.code = make_code()
            self.failures = 0
            self.log("Слишком много неудач, код сопряжения изменён: %s" % self.code)

    def _handshake(self, conn):
        conn.settimeout(15)
        first = recv_plain(conn)
        try:
            peer_x = int(first["X"], 16)
        except (KeyError, ValueError, TypeError):
            raise ProtocolError("некорректное начало рукопожатия")
        sp = Spake2("B", self.code)
        send_plain(conn, {"v": 1, "Y": "%x" % sp.msg, "name": self.name})
        keys = sp.finish(peer_x)
        try:
            c = recv_plain(conn)
            theirs = bytes.fromhex(str(c.get("mac", "")))
        except (ConnectionError, ValueError):
            raise AuthError("отправитель закрыл соединение или прислал мусор")
        if not hmac.compare_digest(theirs, keys.peer_confirm):
            raise AuthError("неверный код сопряжения")
        send_plain(conn, {"mac": keys.my_confirm.hex()})
        return SecureChannel(conn, keys)

    def _session(self, conn, addr):
        """True, если сопряжение прошло (даже если дальше что-то оборвалось)."""
        chan = self._handshake(conn)
        self._paired = True
        self.failures = 0
        conn.settimeout(None)
        m = chan.recv_obj()
        if m.get("type") != "manifest" or not isinstance(m.get("files"), list):
            raise ProtocolError("ожидался манифест")
        files = m["files"]
        if not files or len(files) > MAX_FILES:
            raise ProtocolError("недопустимое число файлов")
        plan = []
        for f in files:
            parts = safe_parts(f.get("path"))
            size, sha = f.get("size"), f.get("sha256")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ProtocolError("недопустимый размер файла")
            if not isinstance(sha, str) or len(sha) != 64:
                raise ProtocolError("недопустимая контрольная сумма")
            plan.append((parts, size, sha.lower()))
        total = sum(p[1] for p in plan)
        sender = str(m.get("sender", "?"))[:80]
        summary = "Принять %d файл(ов), %s от «%s» (%s)?" % (len(plan), human(total), sender, addr[0])

        if not (self.auto_accept or self.ask(summary)):
            chan.send_obj({"accept": False})
            self.log("Отклонено.")
            self.results.append({"sender": sender, "accepted": False, "files": []})
            return True
        if self.auto_accept:
            self.log(summary.replace("Принять", "Принимаю").rstrip("?"))

        base = os.path.realpath(self.out_dir)
        targets, offsets, skips, hashers = [], [], [], []
        for parts, size, sha in plan:
            dest = os.path.join(base, *parts)
            if os.path.commonpath([base, os.path.realpath(os.path.dirname(dest))]) != base:
                raise ProtocolError("путь выходит за пределы папки назначения")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.isfile(dest) and os.path.getsize(dest) == size and sha256_file(dest) == sha:
                targets.append(dest); offsets.append(size); skips.append(True); hashers.append(None)
                continue
            dest = _unique(dest)
            part = dest + ".part"
            h = hashlib.sha256()
            off = 0
            if os.path.isfile(part) and os.path.getsize(part) <= size:
                with open(part, "rb") as pf:
                    for c in iter(lambda: pf.read(1 << 20), b""):
                        h.update(c)
                        off += len(c)
            elif os.path.exists(part):
                os.remove(part)
            targets.append(dest); offsets.append(off); skips.append(False); hashers.append(h)
        chan.send_obj({"accept": True, "offsets": offsets, "skip": skips})

        todo = sum(s - o for (_, s, _), o, k in zip(plan, offsets, skips) if not k)
        prog = Progress(todo, "Приём", self.quiet)
        results = []
        for (parts, size, sha), dest, off, skip, h in zip(plan, targets, offsets, skips, hashers):
            rel = "/".join(parts)
            if skip:
                results.append({"path": rel, "ok": True, "saved_as": dest, "skipped": True})
                self.log("Уже есть, пропускаю: " + rel)
                continue
            part = dest + ".part"
            left = size - off
            with open(part, "ab" if off else "wb") as out:
                while left > 0:
                    data = chan.recv_frame()
                    if not data or len(data) > left:
                        raise ProtocolError("неожиданный размер кадра")
                    out.write(data)
                    h.update(data)
                    left -= len(data)
                    prog.update(len(data))
            if h.hexdigest() == sha:
                os.replace(part, dest)
                results.append({"path": rel, "ok": True, "saved_as": dest})
            else:
                os.remove(part)
                results.append({"path": rel, "ok": False, "saved_as": None})
        prog.finish()
        chan.send_obj({"done": True, "results": [{"path": r["path"], "ok": r["ok"]} for r in results]})
        for r in results:
            if r["ok"] and not r.get("skipped"):
                self.log("Сохранено: " + r["saved_as"])
            elif not r["ok"]:
                self.log("ОШИБКА: контрольная сумма не совпала: " + r["path"])
        self.results.append({"sender": sender, "accepted": True, "files": results})
        return True
