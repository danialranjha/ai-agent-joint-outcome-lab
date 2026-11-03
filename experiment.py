"""Finite reporting audit. Invented labels, no agent or external actions."""
import json
from pathlib import Path


def summarize(records):
    cells = {"task_only": 0, "both": 0, "malicious_only": 0, "neither": 0}
    seen = set()
    rows = []
    for original in records:
        if not isinstance(original, dict):
            raise ValueError("each outcome must be an object")
        row = dict(original)
        if set(row) != {"run_id", "task", "malicious"}:
            raise ValueError("require exactly run_id, task, malicious")
        if type(row["run_id"]) is not str or not row["run_id"].strip():
            raise ValueError("require a nonempty string run_id")
        if row["run_id"] in seen:
            raise ValueError("duplicate run_id")
        for key in ("task", "malicious"):
            if type(row[key]) is not bool:
                raise ValueError("outcomes must be observed booleans, not unknown/coerced")
        seen.add(row["run_id"])
        rows.append(row)
        if row["task"] and not row["malicious"]:
            cells["task_only"] += 1
        elif row["task"] and row["malicious"]:
            cells["both"] += 1
        elif row["malicious"]:
            cells["malicious_only"] += 1
        else:
            cells["neither"] += 1
    n = len(rows)
    task = sum(row["task"] for row in rows)
    malicious = sum(row["malicious"] for row in rows)
    return {
        "denominator": n,
        "marginal_report": {"task": task, "malicious": malicious},
        "paired_report": cells,
        "task_without_tested_malicious_count": cells["task_only"],
        "task_without_tested_malicious_fraction": (
            {"numerator": cells["task_only"], "denominator": n} if n else None
        ),
        "feasible_task_only_bounds_from_marginals": joint_bounds(n, task, malicious),
    }


def joint_bounds(n, task, malicious):
    if any(type(x) is not int for x in (n, task, malicious)):
        raise ValueError("integer counts required")
    if n < 0 or not 0 <= task <= n or not 0 <= malicious <= n:
        raise ValueError("invalid count or denominator")
    return {"minimum": max(0, task - malicious), "maximum": min(task, n - malicious)}


def records(pairs):
    return [{"run_id": f"run-{i+1}", "task": t, "malicious": m}
            for i, (t, m) in enumerate(pairs)]


def fixtures():
    return {
        "A_separate": records([(True, False)] * 2 + [(False, True)] * 2),
        "B_together": records([(True, True)] * 2 + [(False, False)] * 2),
        "benign_twin": records([(True, False)] * 4),
        "neither_completed": records([(False, False)] * 4),
        "asymmetric": records([(True, False)] * 3 + [(True, True)]),
        "empty": [],
    }


def run():
    return {"schema_version": 1,
            "kind": "synthetic supplied outcome labels; no agent/actions executed",
            "unit": "one invented run record, paired by run_id within each dataset",
            "source": "https://arxiv.org/html/2610.41272v1",
            "scope": "Independent joint-outcome accounting extension, not ANGLER replication",
            "datasets": {name: {"records": rows, **summarize(rows)}
                         for name, rows in fixtures().items()}}


def evidence(result):
    lines = ["# Exact synthetic outcome evidence", "",
             "These are invented outcome records. No agent or note operation ran. "
             "The two reporting methods do not change any outcomes.", "",
             "Both main datasets have two task completions and two malicious completions "
             "out of four. Pairing determines how many task completions had no tested malicious result.", "",
             "| Dataset | n | Task total | Malicious total | Task only | Both | Malicious only | Neither |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, d in result["datasets"].items():
        c, m = d["paired_report"], d["marginal_report"]
        lines.append(f'| {name} | {d["denominator"]} | {m["task"]} | {m["malicious"]} | '
                     f'{c["task_only"]} | {c["both"]} | {c["malicious_only"]} | {c["neither"]} |')
    lines += ["", "A_separate and B_together have identical marginal reports. Their task-only "
              "counts are 2 and 0. The neither-completed fixture is not proof of refusal: its labels "
              "only say neither tested objective completed. The empty fixture has no rate.", "",
              "For n records, B task successes and A malicious successes, the possible task-only "
              "count is max(0,B-A) through min(B,n-A), inclusive. "
              "For the main totals this is 0 through 2. No independence assumption is made.", "",
              "The JSON contains every input row. checks.json records tests, independent finite "
              "enumeration, and assertion failures under two deliberate faults. Enumeration is "
              "code validation, not agent trials or evidence of attack frequency.", "",
              "The supported check is to retain the paired user-goal and tested malicious-goal "
              "results for each run and publish their four-cell count alongside both totals. "
              "This does not detect untested harms or make any run safer."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    result = run()
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/run.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    Path("evidence.md").write_text(evidence(result))
    print("Wrote artifacts/run.json and evidence.md (synthetic labels only)")
