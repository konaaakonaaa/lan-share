"""Криптография lan-share: только стандартная библиотека.

ВАЖНО: это учебная реализация, собранная из стандартных примитивов
(hashlib/hmac/secrets). Она НЕ проходила независимый аудит. Для защиты
по-настоящему чувствительных данных используйте проверенные инструменты
(например, magic-wormhole, age, croc).

Схема:
  1. SPAKE2 в подгруппе простого порядка группы MODP-2048 (RFC 3526, группа 14)
     даёт общий секрет из короткого кода сопряжения. Пассивный наблюдатель и
     активный посредник не могут перебирать код офлайн: каждая догадка стоит
     одной онлайн-попытки.
  2. Подтверждение ключей (HMAC) в обе стороны: если коды разные, сессия рвётся.
  3. Канал: поток SHAKE-256 (ключ + номер кадра) для шифрования и HMAC-SHA256
     (encrypt-then-MAC) для целостности. Ключи для двух направлений разные,
     номера кадров защищают от повторов и перестановок.
"""
import hashlib
import hmac
import json
import secrets
import struct

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2          # P - безопасное простое, Q - порядок подгруппы
G = 4                     # квадрат, порождает подгруппу порядка Q
ELEM_LEN = 256
MAX_FRAME = 64 * 1024 * 1024
MAX_PLAIN = 64 * 1024


class AuthError(Exception):
    """Неверный код сопряжения или подмена."""


class ProtocolError(Exception):
    """Нарушение протокола."""


def _hash_to_group(label: bytes) -> int:
    h = int.from_bytes(hashlib.shake_256(b"lanshare-spake2-" + label).digest(320), "big") % P
    return pow(h, 2, P)    # квадрат лежит в подгруппе, а логарифм неизвестен


M = _hash_to_group(b"M")
N = _hash_to_group(b"N")


def normalize_code(code: str) -> str:
    return "-".join(code.strip().lower().split())


def _code_to_w(code: str) -> int:
    d = hashlib.shake_256(b"lanshare-pw-" + normalize_code(code).encode()).digest(64)
    return int.from_bytes(d, "big") % Q


def _enc(n: int) -> bytes:
    return n.to_bytes(ELEM_LEN, "big")


def _kdf(secret: bytes, label: bytes) -> bytes:
    return hmac.new(secret, label, hashlib.sha256).digest()


class SessionKeys:
    def __init__(self, tt: bytes, role: str):
        self.tt = tt
        other = "B" if role == "A" else "A"
        self.my_confirm = hmac.new(_kdf(tt, b"confirm-" + role.encode()), b"confirm" + tt, hashlib.sha256).digest()
        self.peer_confirm = hmac.new(_kdf(tt, b"confirm-" + other.encode()), b"confirm" + tt, hashlib.sha256).digest()
        self.send_enc = _kdf(tt, b"enc-" + role.encode())
        self.send_mac = _kdf(tt, b"mac-" + role.encode())
        self.recv_enc = _kdf(tt, b"enc-" + other.encode())
        self.recv_mac = _kdf(tt, b"mac-" + other.encode())


class Spake2:
    """role "A" - отправитель (клиент), "B" - получатель (сервер)."""

    def __init__(self, role: str, code: str):
        assert role in ("A", "B")
        self.role = role
        self.w = _code_to_w(code)
        self._x = secrets.randbelow(Q - 1) + 1
        self._my_blind = M if role == "A" else N
        self._peer_blind = N if role == "A" else M
        self.msg = (pow(G, self._x, P) * pow(self._my_blind, self.w, P)) % P

    def finish(self, peer_msg: int) -> SessionKeys:
        if not (1 < peer_msg < P - 1) or pow(peer_msg, Q, P) != 1:
            raise ProtocolError("некорректный элемент группы от собеседника")
        unblinded = (peer_msg * pow(self._peer_blind, -self.w, P)) % P
        k = pow(unblinded, self._x, P)
        x_msg, y_msg = (self.msg, peer_msg) if self.role == "A" else (peer_msg, self.msg)
        tt = hashlib.sha256(
            b"lanshare-v1" + _enc(x_msg) + _enc(y_msg) + _enc(k) + _enc(self.w)
        ).digest()
        return SessionKeys(tt, self.role)


# ----------------------------------------------------------- plain framing
def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто собеседником")
        buf += chunk
    return bytes(buf)


def send_plain(sock, obj) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_plain(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_PLAIN:
        raise ProtocolError("слишком большое сообщение рукопожатия")
    try:
        return json.loads(_recv_exact(sock, n))
    except ValueError:
        raise ProtocolError("рукопожатие: не JSON")


# --------------------------------------------------------- secure channel
def _xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


class SecureChannel:
    def __init__(self, sock, keys: SessionKeys):
        self.sock = sock
        self.k = keys
        self._send_seq = 0
        self._recv_seq = 0

    def send_frame(self, data: bytes) -> None:
        seq = struct.pack(">Q", self._send_seq)
        self._send_seq += 1
        ks = hashlib.shake_256(self.k.send_enc + seq).digest(len(data)) if data else b""
        ct = _xor(data, ks)
        tag = hmac.new(self.k.send_mac, seq + ct, hashlib.sha256).digest()
        self.sock.sendall(struct.pack(">I", len(ct)) + ct + tag)

    def recv_frame(self) -> bytes:
        (n,) = struct.unpack(">I", _recv_exact(self.sock, 4))
        if n > MAX_FRAME:
            raise ProtocolError("слишком большой кадр")
        ct = _recv_exact(self.sock, n)
        tag = _recv_exact(self.sock, 32)
        seq = struct.pack(">Q", self._recv_seq)
        expect = hmac.new(self.k.recv_mac, seq + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            raise AuthError("кадр не прошёл проверку целостности")
        self._recv_seq += 1
        ks = hashlib.shake_256(self.k.recv_enc + seq).digest(n) if n else b""
        return _xor(ct, ks)

    def send_obj(self, obj) -> None:
        self.send_frame(json.dumps(obj).encode())

    def recv_obj(self):
        try:
            return json.loads(self.recv_frame())
        except ValueError:
            raise ProtocolError("ожидался JSON")
