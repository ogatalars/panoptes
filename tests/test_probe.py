import json
import unittest

from panoptes import incident, probe


class Predicate(unittest.TestCase):
    def test_is_good(self):
        self.assertTrue(probe.is_good(200, 500, 2000))
        self.assertTrue(probe.is_good(204, 2000, 2000))
        self.assertFalse(probe.is_good(200, 2001, 2000))  # too slow counts as bad
        self.assertFalse(probe.is_good(301, 10, 2000))
        self.assertFalse(probe.is_good(503, 10, 2000))
        self.assertFalse(probe.is_good(0, 10, 2000))  # no response


class Tls(unittest.TestCase):
    def test_days_until(self):
        not_after = "Jan  2 00:00:00 2030 GMT"
        exp = probe.ssl.cert_time_to_seconds(not_after)
        self.assertEqual(probe.days_until(not_after, exp - 10 * 86400), 10.0)
        self.assertEqual(probe.days_until(not_after, exp + 86400), -1.0)


class Posture(unittest.TestCase):
    def states(self, headers, body="", configurable=False):
        return {c["header"]: c["state"] for c in probe.security_posture(headers, body, configurable)}

    def test_github_pages_absence_is_platform_limit(self):
        s = self.states({"strict-transport-security": "max-age=31556952"})
        self.assertEqual(s["HSTS"], "ok")
        self.assertEqual(s["X-Content-Type-Options"], "platform")

    def test_absence_is_missing_when_host_can_set_headers(self):
        self.assertEqual(self.states({}, configurable=True)["HSTS"], "missing")

    def test_meta_tags_count(self):
        body = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><meta name="referrer" content="no-referrer">'
        s = self.states({}, body)
        self.assertEqual(s["Content-Security-Policy"], "meta")
        self.assertEqual(s["Referrer-Policy"], "meta")
        self.assertEqual(s["X-Frame-Options"], "platform")  # cannot be set via meta


class Completion(unittest.TestCase):
    def test_parses_openai_shape(self):
        raw = json.dumps({"choices": [{"message": {"content": "  draft  "}}]})
        self.assertEqual(incident.parse_completion(raw), "draft")

    def test_garbage_returns_none(self):
        for raw in (b"OK", b"{}", json.dumps({"choices": []}), json.dumps({"choices": [{"message": {"content": None}}]})):
            self.assertIsNone(incident.parse_completion(raw))


if __name__ == "__main__":
    unittest.main()
