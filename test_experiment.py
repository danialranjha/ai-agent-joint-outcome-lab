import itertools
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from experiment import fixtures, joint_bounds, records, run, summarize


def exhaustive_check():
    sequence_count = group_count = 0
    outcomes = [(False, False), (False, True), (True, False), (True, True)]
    for n in range(7):
        ranges = {}
        for seq in itertools.product(outcomes, repeat=n):
            # Independent direct tuple counting, not the production classifier.
            b = sum(t for t, m in seq)
            a = sum(m for t, m in seq)
            target = seq.count((True, False))
            ranges.setdefault((b, a), set()).add(target)
            d = summarize(records(seq))
            assert d["task_without_tested_malicious_count"] == target
            assert sum(d["paired_report"].values()) == n
            sequence_count += 1
        for (b, a), observed in ranges.items():
            bound = joint_bounds(n, b, a)
            assert observed == set(range(bound["minimum"], bound["maximum"] + 1))
            group_count += 1
    return {"max_sequence_length": 6, "sequences": sequence_count,
            "marginal_groups": group_count, "passed": True}


class OutcomeTests(unittest.TestCase):
    def test_same_marginals_different_joint(self):
        ds = run()["datasets"]
        a, b = ds["A_separate"], ds["B_together"]
        self.assertEqual(a["marginal_report"], {"task": 2, "malicious": 2})
        self.assertEqual(a["marginal_report"], b["marginal_report"])
        self.assertEqual((a["task_without_tested_malicious_count"],
                          b["task_without_tested_malicious_count"]), (2, 0))

    def test_every_cell_and_asymmetric(self):
        self.assertEqual(summarize(records([(False, False), (False, True),
                                          (True, False), (True, True)]))["paired_report"],
                         {"task_only": 1, "both": 1, "malicious_only": 1, "neither": 1})
        self.assertEqual(summarize(fixtures()["asymmetric"])["task_without_tested_malicious_count"], 3)

    def test_twins(self):
        self.assertEqual(summarize(fixtures()["benign_twin"])["task_without_tested_malicious_count"], 4)
        d = summarize(fixtures()["neither_completed"])
        self.assertEqual(d["marginal_report"], {"task": 0, "malicious": 0})
        self.assertEqual(d["task_without_tested_malicious_count"], 0)

    def test_missing_unknown_and_nonboolean(self):
        invalid = [{"run_id": "a", "task": True}, {"run_id": "a", "malicious": False}]
        for field in ("task", "malicious"):
            for value in (None, 0, 1, "false", [], {}):
                row = {"run_id": "a", "task": True, "malicious": False}
                row[field] = value
                invalid.append(row)
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(ValueError):
                summarize([row])

    def test_identity_and_shape(self):
        valid = {"run_id": "a", "task": True, "malicious": False}
        for rows in ([valid, valid], [{**valid, "run_id": ""}], [{**valid, "run_id": 1}],
                     [{**valid, "extra": False}], [None], [{"task": True, "malicious": False}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                summarize(rows)

    def test_empty_and_reordering(self):
        d = summarize([])
        self.assertEqual(d["denominator"], 0)
        self.assertIsNone(d["task_without_tested_malicious_fraction"])
        rows = fixtures()["A_separate"]
        self.assertEqual(summarize(rows), summarize(list(reversed(rows))))

    def test_invalid_bounds(self):
        for args in [(-1, 0, 0), (2, 3, 0), (2, 0, -1), (2, 1, 3), (True, 1, 1), (2, 1.0, 0)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                joint_bounds(*args)

    def test_exhaustive(self):
        result = exhaustive_check()
        self.assertEqual(result["sequences"], sum(4**n for n in range(7)))
        self.assertEqual(result["marginal_groups"], sum((n+1)**2 for n in range(7)))

    def test_input_unchanged(self):
        rows = fixtures()["A_separate"]
        before = json.dumps(rows)
        summarize(rows)
        self.assertEqual(json.dumps(rows), before)


def validate():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OutcomeTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    source = Path("experiment.py").read_text()
    faults = {
        "intersection_instead_of_task_only": ('if row["task"] and not row["malicious"]:',
                                               'if row["task"] and row["malicious"]:'),
        "missing_becomes_false": ('row = dict(original)',
                                   'row = {"task": False, "malicious": False, **original}'),
    }
    mutations = {}
    for name, (old, new) in faults.items():
        assert source.count(old) == 1
        with tempfile.TemporaryDirectory(prefix="joint-outcome-fault-") as tmp:
            p = Path(tmp)
            (p/"experiment.py").write_text(source.replace(old, new))
            (p/"test_experiment.py").write_bytes(Path(__file__).read_bytes())
            proc = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v"],
                                  cwd=p, capture_output=True, text=True, timeout=30)
            failures = len(re.findall(r"^FAIL:", proc.stderr, re.M))
            errors = len(re.findall(r"^ERROR:", proc.stderr, re.M))
            if proc.returncode == 0 or failures == 0 or errors != 0:
                raise AssertionError(f"fault not caught by assertions: {name}: {proc.stderr}")
            mutations[name] = {"exit_code": proc.returncode, "assertion_failures": failures, "errors": errors}
    checks = {"unit_tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "exhaustive": exhaustive_check(), "deliberate_faults": mutations}
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/checks.json").write_text(json.dumps(checks, indent=2, sort_keys=True) + "\n")
    print(json.dumps(checks, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["--validate"]:
        validate()
    else:
        unittest.main()
