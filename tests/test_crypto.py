import socket
import unittest

from lanshare import crypto as c


class Spake(unittest.TestCase):
    def pair(self, code_a, code_b):
        a, b = c.Spake2("A", code_a), c.Spake2("B", code_b)
        return a.finish(b.msg), b.finish(a.msg)

    def test_same_code_same_keys(self):
        ka, kb = self.pair("42-apple-river", "42-apple-river")
        self.assertEqual(ka.tt, kb.tt)
        self.assertEqual(ka.my_confirm, kb.peer_confirm)
        self.assertEqual(kb.my_confirm, ka.peer_confirm)
        self.assertEqual(ka.send_enc, kb.recv_enc)
        self.assertEqual(ka.recv_mac, kb.send_mac)
        self.assertNotEqual(ka.send_enc, ka.recv_enc)

    def test_code_normalised(self):
        ka, kb = self.pair("42-Apple-River", "  42-apple-river ")
        self.assertEqual(ka.tt, kb.tt)

    def test_wrong_code_different_keys(self):
        ka, kb = self.pair("42-apple-river", "43-apple-river")
        self.assertNotEqual(ka.tt, kb.tt)
        self.assertNotEqual(ka.my_confirm, kb.peer_confirm)

    def test_sessions_are_fresh(self):
        k1, _ = self.pair("1-a-b", "1-a-b")
        k2, _ = self.pair("1-a-b", "1-a-b")
        self.assertNotEqual(k1.tt, k2.tt)

    def test_bad_group_elements_rejected(self):
        a = c.Spake2("A", "1-a-b")
        for bad in (0, 1, c.P - 1, c.P, c.P + 5, 2 * c.P, -3):
            with self.assertRaises(c.ProtocolError):
                a.finish(bad)
        # не принадлежит подгруппе порядка Q: невычет
        nonresidue = c.P - 4  # -(2^2) - невычет, так как p = 3 mod 4
        self.assertNotEqual(pow(nonresidue, c.Q, c.P), 1)
        with self.assertRaises(c.ProtocolError):
            a.finish(nonresidue)


class Channel(unittest.TestCase):
    def setUp(self):
        self.s1, self.s2 = socket.socketpair()
        a, b = c.Spake2("A", "5-x-y"), c.Spake2("B", "5-x-y")
        ka, kb = a.finish(b.msg), b.finish(a.msg)
        self.ca, self.cb = c.SecureChannel(self.s1, ka), c.SecureChannel(self.s2, kb)

    def tearDown(self):
        self.s1.close()
        self.s2.close()

    def test_roundtrip_both_directions(self):
        for payload in (b"", b"x", b"\x00" * 1000, bytes(range(256)) * 400):
            self.ca.send_frame(payload)
            self.assertEqual(self.cb.recv_frame(), payload)
            self.cb.send_frame(payload[::-1])
            self.assertEqual(self.ca.recv_frame(), payload[::-1])

    def test_ciphertext_differs_from_plaintext(self):
        self.ca.send_frame(b"A" * 100)
        raw = self.s2.recv(4 + 100 + 32)
        self.assertNotIn(b"AAAA", raw)

    def test_same_plaintext_different_ciphertext(self):
        self.ca.send_frame(b"hello world")
        r1 = self.s2.recv(4 + 11 + 32)
        self.ca.send_frame(b"hello world")
        r2 = self.s2.recv(4 + 11 + 32)
        self.assertNotEqual(r1[4:15], r2[4:15])

    def test_tamper_detected(self):
        self.ca.send_frame(b"important data")
        raw = bytearray(self.s2.recv(4 + 14 + 32))
        raw[6] ^= 1
        a, b = socket.socketpair()
        a.sendall(bytes(raw))
        # тот же ключ, но другая пара сокетов
        ch = c.SecureChannel(b, self.cb.k)
        with self.assertRaises(c.AuthError):
            ch.recv_frame()
        a.close(); b.close()

    def test_replay_and_reorder_detected(self):
        self.ca.send_frame(b"one")
        f1 = self.s2.recv(4 + 3 + 32)
        self.ca.send_frame(b"two")
        f2 = self.s2.recv(4 + 3 + 32)
        a, b = socket.socketpair()
        ch = c.SecureChannel(b, self.cb.k)
        a.sendall(f2)                       # кадр №2 раньше №1
        with self.assertRaises(c.AuthError):
            ch.recv_frame()
        a.close(); b.close()
        a, b = socket.socketpair()
        ch = c.SecureChannel(b, self.cb.k)
        a.sendall(f1 + f1)                  # повтор кадра №1
        self.assertEqual(ch.recv_frame(), b"one")
        with self.assertRaises(c.AuthError):
            ch.recv_frame()
        a.close(); b.close()

    def test_oversized_frame_rejected(self):
        import struct
        self.s1.sendall(struct.pack(">I", c.MAX_FRAME + 1))
        with self.assertRaises(c.ProtocolError):
            self.cb.recv_frame()


if __name__ == "__main__":
    unittest.main()
