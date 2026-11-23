import unittest

from panoptes import slo

NOW = 1_000_000


def series(goods, step=900, end=NOW):
    """Samples ending at `end`, one per `step` seconds, from a list of 1/0."""
    n = len(goods)
    return [[end - (n - 1 - i) * step, 200 if g else 500, 100, g] for i, g in enumerate(goods)]


class SliAndBudget(unittest.TestCase):
    def test_sli(self):
        self.assertIsNone(slo.sli([]))
        self.assertEqual(slo.sli(series([1, 1, 1, 0])), 0.75)

    def test_budget_untouched_spent_overspent(self):
        self.assertAlmostEqual(slo.error_budget_remaining(1.0, 0.995), 1.0)
        self.assertAlmostEqual(slo.error_budget_remaining(0.995, 0.995), 0.0)
        self.assertAlmostEqual(slo.error_budget_remaining(0.9975, 0.995), 0.5)
        self.assertAlmostEqual(slo.error_budget_remaining(0.99, 0.995), -1.0)
        self.assertIsNone(slo.error_budget_remaining(None, 0.995))

    def test_slo_stricter_than_sla_spends_budget_first(self):
        sli = 0.993
        self.assertLess(slo.error_budget_remaining(sli, 0.995), 0)  # internal SLO blown
        self.assertGreater(slo.error_budget_remaining(sli, 0.99), 0)  # public SLA still met

    def test_burn_rate(self):
        self.assertEqual(slo.burn_rate([], 0.995), 0.0)
        # 1 bad out of 200 at a 99.5% objective = exactly on budget
        self.assertAlmostEqual(slo.burn_rate(series([0] + [1] * 199), 0.995), 1.0)
        self.assertAlmostEqual(slo.burn_rate(series([0, 1, 1, 1]), 0.995), 50.0)


class Alerts(unittest.TestCase):
    def firing(self, samples):
        return {a["rule"]: a["firing"] for a in slo.evaluate_alerts(samples, NOW, 0.995)}

    def test_healthy_fires_nothing(self):
        self.assertFalse(any(self.firing(series([1] * 300)).values()))

    def test_single_blip_does_not_page(self):
        self.assertFalse(any(self.firing(series([1] * 299 + [0])).values()))

    def test_recent_failures_page_fast_and_slow(self):
        f = self.firing(series([1] * 298 + [0, 0]))
        self.assertTrue(f["fast"])
        self.assertTrue(f["slow"])

    def test_old_failures_need_short_window_too(self):
        # two failures 5h ago: long 6h window burns, short 1h window is clean
        goods = [1] * 280 + [0, 0] + [1] * 18
        self.assertFalse(self.firing(series(goods))["slow"])

    def test_is_down(self):
        self.assertTrue(slo.is_down(series([1, 0, 0])))
        self.assertFalse(slo.is_down(series([0, 0, 1])))
        self.assertFalse(slo.is_down(series([0])))


class Coverage(unittest.TestCase):
    def test_perfect_and_gappy(self):
        self.assertEqual(slo.coverage(series([1] * 5), NOW, 900)["ratio"], 1.0)
        gappy = [s for i, s in enumerate(series([1] * 9)) if i not in (3, 4, 5)]
        c = slo.coverage(gappy, NOW, 900)
        self.assertEqual((c["observed"], c["expected"], c["max_gap_min"]), (6, 9, 60.0))

    def test_empty(self):
        self.assertIsNone(slo.coverage([], NOW, 900)["ratio"])


if __name__ == "__main__":
    unittest.main()
