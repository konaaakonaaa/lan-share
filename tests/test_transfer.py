import os
import shutil
import socket
import tempfile
import threading
import unittest

from lanshare import transfer
from lanshare.crypto import AuthError, ProtocolError, Spake2, SecureChannel
from tests.helpers import Rx, read, sha, write


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        os.makedirs(self.src)
        self.rxs = []

    def tearDown(self):
        for r in self.rxs:
            r.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rx(self, **kw):
        r = Rx(self.dst, **kw)
        self.rxs.append(r)
        return r


class SingleFile(Base):
    def roundtrip(self, size):
        f = write(os.path.join(self.src, "a.bin"), os.urandom(size))
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        res = r.join()
        out = os.path.join(self.dst, "a.bin")
        self.assertTrue(res[0]["accepted"])
        self.assertEqual(os.path.getsize(out), size)
        self.assertEqual(sha(out), sha(f))
        self.assertFalse(os.path.exists(out + ".part"))

    def test_empty(self): self.roundtrip(0)
    def test_one_byte(self): self.roundtrip(1)
    def test_odd_size(self): self.roundtrip(transfer.CHUNK * 3 + 17)
    def test_exact_chunk(self): self.roundtrip(transfer.CHUNK)
    def test_20mb(self): self.roundtrip(20 * 1024 * 1024)

    def test_unicode_name(self):
        f = write(os.path.join(self.src, "файл тест №1.txt"), b"privet")
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        r.join()
        self.assertEqual(read(os.path.join(self.dst, "файл тест №1.txt")), b"privet")


class Folders(Base):
    def test_folder_tree(self):
        root = os.path.join(self.src, "proj")
        write(os.path.join(root, "a.txt"), b"A")
        write(os.path.join(root, "sub", "b.txt"), b"B" * 1000)
        write(os.path.join(root, "sub", "deep", "c.bin"), os.urandom(500_000))
        write(os.path.join(root, "empty.txt"), b"")
        r = self.rx()
        transfer.send(r.addr, [root], r.code)
        r.join()
        for rel in ("a.txt", "sub/b.txt", "sub/deep/c.bin", "empty.txt"):
            self.assertEqual(sha(os.path.join(self.dst, "proj", *rel.split("/"))),
                             sha(os.path.join(root, *rel.split("/"))), rel)

    def test_mixed_file_and_folder(self):
        f = write(os.path.join(self.src, "one.txt"), b"1")
        d = os.path.join(self.src, "dir")
        write(os.path.join(d, "two.txt"), b"2")
        r = self.rx()
        transfer.send(r.addr, [f, d], r.code)
        r.join()
        self.assertTrue(os.path.isfile(os.path.join(self.dst, "one.txt")))
        self.assertTrue(os.path.isfile(os.path.join(self.dst, "dir", "two.txt")))

    @unittest.skipIf(not hasattr(os, "symlink"), "нет симлинков")
    def test_symlinks_skipped(self):
        root = os.path.join(self.src, "p")
        write(os.path.join(root, "real.txt"), b"x")
        secret = write(os.path.join(self.tmp, "secret.txt"), b"SECRET")
        try:
            os.symlink(secret, os.path.join(root, "link.txt"))
        except OSError:
            self.skipTest("симлинки недоступны")
        r = self.rx()
        transfer.send(r.addr, [root], r.code)
        r.join()
        self.assertTrue(os.path.exists(os.path.join(self.dst, "p", "real.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "p", "link.txt")))

    def test_duplicate_names_rejected(self):
        a = write(os.path.join(self.src, "x", "same.txt"), b"1")
        b = write(os.path.join(self.src, "y", "same.txt"), b"2")
        with self.assertRaises(ValueError):
            transfer.collect([a, b])

    def test_nothing_to_send(self):
        os.makedirs(os.path.join(self.src, "emptydir"))
        with self.assertRaises(ValueError):
            transfer.collect([os.path.join(self.src, "emptydir")])


class Auth(Base):
    def test_wrong_code_rejected_and_receiver_survives(self):
        f = write(os.path.join(self.src, "a.txt"), b"data")
        r = self.rx()
        with self.assertRaises(AuthError):
            transfer.send(r.addr, [f], "00-wrong-code")
        self.assertFalse(os.path.exists(os.path.join(self.dst, "a.txt")))
        transfer.send(r.addr, [f], r.code)      # правильный код после неудачи
        r.join()
        self.assertTrue(os.path.exists(os.path.join(self.dst, "a.txt")))

    def test_code_rotates_after_failures(self):
        f = write(os.path.join(self.src, "a.txt"), b"data")
        r = self.rx(max_failures=2)
        old = r.code
        for _ in range(2):
            with self.assertRaises(AuthError):
                transfer.send(r.addr, [f], "00-bad-bad")
        self.assertNotEqual(r.rx.code, old)
        with self.assertRaises(AuthError):
            transfer.send(r.addr, [f], old)

    def test_garbage_does_not_end_once_receiver(self):
        f = write(os.path.join(self.src, "a.txt"), b"data")
        r = self.rx()
        s = socket.create_connection(("127.0.0.1", r.port))
        s.sendall(b"GET / HTTP/1.1\r\n\r\n")
        s.close()
        transfer.send(r.addr, [f], r.code)
        r.join()
        self.assertTrue(os.path.exists(os.path.join(self.dst, "a.txt")))


class Decline(Base):
    def test_declined(self):
        f = write(os.path.join(self.src, "a.txt"), b"data")
        r = self.rx(auto_accept=False, ask=lambda text: False)
        with self.assertRaises(transfer.Declined):
            transfer.send(r.addr, [f], r.code)
        res = r.join()
        self.assertFalse(res[0]["accepted"])
        self.assertFalse(os.path.exists(os.path.join(self.dst, "a.txt")))

    def test_accept_callback_sees_summary(self):
        f = write(os.path.join(self.src, "a.txt"), b"data")
        seen = []
        r = self.rx(auto_accept=False, ask=lambda t: seen.append(t) or True)
        transfer.send(r.addr, [f], r.code, name="Маша")
        r.join()
        self.assertIn("Маша", seen[0])
        self.assertIn("1 файл", seen[0])


class Conflicts(Base):
    def test_identical_existing_skipped(self):
        f = write(os.path.join(self.src, "a.txt"), b"same")
        write(os.path.join(self.dst, "a.txt"), b"same")
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        res = r.join()
        self.assertTrue(res[0]["files"][0].get("skipped"))
        self.assertEqual(os.listdir(self.dst), ["a.txt"])

    def test_different_existing_not_overwritten(self):
        f = write(os.path.join(self.src, "a.txt"), b"new content")
        write(os.path.join(self.dst, "a.txt"), b"OLD")
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        r.join()
        self.assertEqual(read(os.path.join(self.dst, "a.txt")), b"OLD")
        self.assertEqual(read(os.path.join(self.dst, "a (1).txt")), b"new content")


class Resume(Base):
    def test_resume_from_part(self):
        data = os.urandom(transfer.CHUNK * 4 + 123)
        f = write(os.path.join(self.src, "big.bin"), data)
        cut = transfer.CHUNK * 2 + 7
        write(os.path.join(self.dst, "big.bin.part"), data[:cut])
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        r.join()
        self.assertEqual(sha(os.path.join(self.dst, "big.bin")), sha(f))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "big.bin.part")))

    def test_resume_sends_only_remainder(self):
        data = os.urandom(transfer.CHUNK * 4)
        f = write(os.path.join(self.src, "big.bin"), data)
        write(os.path.join(self.dst, "big.bin.part"), data[: transfer.CHUNK * 3])
        r = self.rx()
        sent = []
        orig = SecureChannel.send_frame
        def spy(self_, d):
            sent.append(len(d)); return orig(self_, d)
        SecureChannel.send_frame = spy
        try:
            transfer.send(r.addr, [f], r.code)
        finally:
            SecureChannel.send_frame = orig
        r.join()
        data_frames = [n for n in sent if n == transfer.CHUNK]   # служебные кадры маленькие
        self.assertEqual(len(data_frames), 1)                    # из 4 чанков осталось докачать 1

    def test_corrupt_part_detected_by_hash(self):
        data = os.urandom(transfer.CHUNK * 2)
        f = write(os.path.join(self.src, "x.bin"), data)
        bad = bytearray(data[: transfer.CHUNK]); bad[10] ^= 0xFF
        write(os.path.join(self.dst, "x.bin.part"), bytes(bad))
        r = self.rx()
        with self.assertRaises(ProtocolError):
            transfer.send(r.addr, [f], r.code)
        res = r.join()
        self.assertFalse(res[0]["files"][0]["ok"])
        self.assertFalse(os.path.exists(os.path.join(self.dst, "x.bin")))

    def test_oversized_part_discarded(self):
        f = write(os.path.join(self.src, "x.txt"), b"short")
        write(os.path.join(self.dst, "x.txt.part"), b"way too long for this file")
        r = self.rx()
        transfer.send(r.addr, [f], r.code)
        r.join()
        self.assertEqual(read(os.path.join(self.dst, "x.txt")), b"short")


class Malicious(Base):
    """Подключаемся «вручную» с правильным кодом, но врём в манифесте."""

    def attack(self, files):
        r = self.rx()
        s = socket.create_connection(("127.0.0.1", r.port), timeout=5)
        chan, _ = transfer.client_handshake(s, r.code)
        chan.send_obj({"type": "manifest", "sender": "evil", "files": files})
        try:
            s.settimeout(5)
            chan.recv_obj()
        except Exception:
            pass
        s.close()
        r.join()

    def test_path_traversal_blocked(self):
        for evil in ("../evil.txt", "a/../../evil.txt", "/etc/evil", "..", "a//b", "C:/evil", "a\\..\\b", "./x"):
            self.setUp_clean()
            self.attack([{"path": evil, "size": 1, "sha256": "0" * 64}])
            self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")), evil)
            self.assertFalse(os.path.exists("/etc/evil"))
            self.assertEqual([x for x in os.listdir(self.dst)], [], evil)
            self.tearDown_rx()

    def setUp_clean(self):
        shutil.rmtree(self.dst, ignore_errors=True)
        os.makedirs(self.dst)

    def tearDown_rx(self):
        for r in self.rxs:
            r.close()
        self.rxs = []

    def test_bad_sizes_and_hashes(self):
        for f in ({"path": "a", "size": -1, "sha256": "0" * 64},
                  {"path": "a", "size": "5", "sha256": "0" * 64},
                  {"path": "a", "size": True, "sha256": "0" * 64},
                  {"path": "a", "size": 1, "sha256": "short"},
                  {"path": 5, "size": 1, "sha256": "0" * 64}):
            self.setUp_clean()
            self.attack([f])
            self.assertEqual(os.listdir(self.dst), [], f)
            self.tearDown_rx()

    def test_lying_hash_leaves_no_file(self):
        r = self.rx()
        s = socket.create_connection(("127.0.0.1", r.port), timeout=5)
        chan, _ = transfer.client_handshake(s, r.code)
        chan.send_obj({"type": "manifest", "sender": "x",
                       "files": [{"path": "f.txt", "size": 4, "sha256": "0" * 64}]})
        self.assertTrue(chan.recv_obj()["accept"])
        chan.send_frame(b"abcd")
        done = chan.recv_obj()
        s.close()
        r.join()
        self.assertFalse(done["results"][0]["ok"])
        self.assertEqual(os.listdir(self.dst), [])

    def test_extra_data_beyond_size_rejected(self):
        r = self.rx()
        s = socket.create_connection(("127.0.0.1", r.port), timeout=5)
        chan, _ = transfer.client_handshake(s, r.code)
        chan.send_obj({"type": "manifest", "sender": "x",
                       "files": [{"path": "f.txt", "size": 2, "sha256": "0" * 64}]})
        chan.recv_obj()
        chan.send_frame(b"toolong")
        s.close()
        r.join()
        self.assertFalse(os.path.exists(os.path.join(self.dst, "f.txt")))


class Broken(Base):
    def test_connection_drop_keeps_part_then_resume_works(self):
        data = os.urandom(transfer.CHUNK * 6)
        f = write(os.path.join(self.src, "big.bin"), data)
        r1 = self.rx(once=False)
        # «обрыв»: вручную шлём два чанка и закрываем сокет
        import hashlib
        s = socket.create_connection(("127.0.0.1", r1.port), timeout=5)
        chan, _ = transfer.client_handshake(s, r1.code)
        chan.send_obj({"type": "manifest", "sender": "x", "files": [
            {"path": "big.bin", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]})
        chan.recv_obj()
        chan.send_frame(data[: transfer.CHUNK])
        chan.send_frame(data[transfer.CHUNK: transfer.CHUNK * 2])
        s.close()
        import time
        for _ in range(50):
            if os.path.exists(os.path.join(self.dst, "big.bin.part")) and \
               os.path.getsize(os.path.join(self.dst, "big.bin.part")) >= transfer.CHUNK * 2:
                break
            time.sleep(0.05)
        self.assertEqual(os.path.getsize(os.path.join(self.dst, "big.bin.part")), transfer.CHUNK * 2)
        self.assertFalse(os.path.exists(os.path.join(self.dst, "big.bin")))
        transfer.send(r1.addr, [f], r1.code)          # докачка
        for _ in range(50):
            if os.path.exists(os.path.join(self.dst, "big.bin")):
                break
            time.sleep(0.05)
        self.assertEqual(sha(os.path.join(self.dst, "big.bin")), sha(f))


class MultiRecipient(Base):
    def test_two_receivers_in_parallel(self):
        f = write(os.path.join(self.src, "big.bin"), os.urandom(3_000_000))
        d1, d2 = os.path.join(self.tmp, "d1"), os.path.join(self.tmp, "d2")
        r1, r2 = Rx(d1), Rx(d2)
        self.rxs += [r1, r2]
        errs = []
        def go(r):
            try:
                transfer.send(r.addr, [f], r.code)
            except Exception as e:
                errs.append(e)
        ts = [threading.Thread(target=go, args=(r,)) for r in (r1, r2)]
        [t.start() for t in ts]; [t.join(20) for t in ts]
        self.assertEqual(errs, [])
        for d in (d1, d2):
            self.assertEqual(sha(os.path.join(d, "big.bin")), sha(f))


class Misc(unittest.TestCase):
    def test_bad_address(self):
        with self.assertRaises(ValueError):
            transfer.send("no-port", [__file__], "1-a-b")

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            transfer.send("127.0.0.1:1", ["/no/such/file"], "1-a-b")

    def test_nobody_listening(self):
        with self.assertRaises(OSError):
            transfer.send("127.0.0.1:1", [__file__], "1-a-b")

    def test_make_code_format(self):
        for _ in range(50):
            n, w1, w2 = transfer.make_code().split("-")
            self.assertTrue(10 <= int(n) <= 99)
            self.assertIn(w1, transfer._WORDS)

    def test_human(self):
        self.assertEqual(transfer.human(0), "0 Б")
        self.assertEqual(transfer.human(1536), "1.5 КБ")
        self.assertEqual(transfer.human(5 * 1024 ** 3), "5.0 ГБ")


if __name__ == "__main__":
    unittest.main()
