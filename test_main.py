import json
import unittest
from main import detect

def event(second, outcome='failure', ip='192.0.2.10', user='student'):
    return json.dumps({'timestamp': f'2026-11-06T00:{second//60:02d}:{second%60:02d}Z', 'source_ip': ip, 'user': user, 'outcome': outcome})

class DetectionTests(unittest.TestCase):
    def test_burst_and_success(self):
        self.assertEqual([x['rule'] for x in detect([event(0),event(10),event(20),event(30,'success')])], ['failure-burst','success-after-failures'])
    def test_window_expires(self):
        self.assertEqual(detect([event(0),event(61),event(122)]), [])
    def test_boundary_included(self):
        self.assertEqual(len(detect([event(0),event(30),event(60)])),1)
    def test_users_isolated(self):
        self.assertEqual(detect([event(0),event(1,user='other'),event(2)]),[])
    def test_success_resets(self):
        self.assertEqual(detect([event(0),event(1,'success'),event(2),event(3)]),[])
    def test_sorts_input(self):
        self.assertEqual(len(detect([event(20),event(0),event(10)])),1)
    def test_bad_ip(self):
        with self.assertRaises(ValueError): detect([event(0,ip='bad')])
    def test_bad_threshold(self):
        with self.assertRaises(ValueError): detect([],threshold=0)
    def test_empty(self):
        self.assertEqual(detect([]),[])
