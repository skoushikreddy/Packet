"""
NetScope Test Suite
Unit tests for protocol analysis, filter parser, and SQLite operations.
"""

import unittest
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analyzers.filter_parser import translate_filter_to_bpf
from backend.database import db


class TestNetScope(unittest.TestCase):

    def setUp(self):
        db.init_db()

    def test_filter_translation_tcp(self):
        is_valid, bpf, err = translate_filter_to_bpf("tcp")
        self.assertTrue(is_valid)
        self.assertEqual(bpf, "tcp")
        self.assertIsNone(err)

    def test_filter_translation_ip_src(self):
        is_valid, bpf, err = translate_filter_to_bpf("ip.src == 192.168.1.10")
        self.assertTrue(is_valid)
        self.assertEqual(bpf, "src host 192.168.1.10")

    def test_filter_translation_port(self):
        is_valid, bpf, err = translate_filter_to_bpf("tcp.port == 443")
        self.assertTrue(is_valid)
        self.assertEqual(bpf, "tcp port 443")

    def test_filter_translation_invalid(self):
        is_valid, bpf, err = translate_filter_to_bpf("nonexistent_protocol_xyz == 999999")
        self.assertFalse(is_valid)
        self.assertIsNotNone(err)

    def test_database_session_crud(self):
        test_session_id = "test_sess_001"
        db.create_session(test_session_id, "Unit Test Session", "eth0", 1700000000000)

        sessions = db.get_all_sessions()
        self.assertTrue(any(s["id"] == test_session_id for s in sessions))

        db.delete_session(test_session_id)
        sessions_after = db.get_all_sessions()
        self.assertFalse(any(s["id"] == test_session_id for s in sessions_after))


if __name__ == "__main__":
    unittest.main()
