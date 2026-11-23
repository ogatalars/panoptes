import unittest

from panoptes import scan


class Counts(unittest.TestCase):
    def test_trivy(self):
        report = {"Results": [
            {"Vulnerabilities": [{"Severity": "HIGH"}, {"Severity": "HIGH"}, {"Severity": "LOW"}]},
            {"Secrets": [{"Severity": "CRITICAL"}], "Misconfigurations": None},
        ]}
        self.assertEqual(scan.trivy_counts(report), {
            "vulnerabilities": {"HIGH": 2, "LOW": 1}, "secrets": {"CRITICAL": 1}, "misconfigurations": {}})
        self.assertEqual(scan.trivy_counts({})["secrets"], {})  # clean repo: no Results key

    def test_semgrep(self):
        report = {"results": [{"extra": {"severity": "ERROR"}}, {"extra": {"severity": "WARNING"}}, {"extra": {}}]}
        self.assertEqual(scan.semgrep_counts(report), {"ERROR": 1, "WARNING": 1, "UNKNOWN": 1})


if __name__ == "__main__":
    unittest.main()
