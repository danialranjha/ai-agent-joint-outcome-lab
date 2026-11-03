# AI-agent evaluation: keep outcome pairs

Separate task-success and malicious-success totals do not determine how many runs completed the task without the tested malicious outcome. This is a small, independently authored reporting experiment with **invented Boolean outcome records**. No AI model, browser, website, note operation, network request or attack runs.

## Hypothesis and threat model

Two datasets can have identical denominators and identical task/malicious totals, but different co-occurrence. The risk is an evaluation consumer inferring a joint outcome from marginal totals. No compromised system or attacker is simulated. The supplied outcome labels, run IDs and calculation remain trusted. We test the calculation, not the truth of those labels.

The motivating [ANGLER v1 paper, sections3.1 and4.3](https://arxiv.org/html/2610.41272v1) defines separate user-goal and malicious-goal verifiers. This lab asks an additional accounting question. The marginal-only report is our control, not an allegation about the paper's evaluator. None of its live-agent results is reproduced or used as synthetic data here.

## Two reports of the same records

- **Separate totals:** Count requested-task completion and tested malicious-objective completion independently.
- **Paired outcomes:** Keep those totals and count task only, both, malicious only and neither on the same run IDs.

For a hypothetical note app, the requested task is saving a private note and the malicious objective is creating an unrelated public note. These can both happen, either can happen alone, or neither can happen. No such actions execute; these meanings explain supplied labels only.

The A and B datasets are not two defenses. The two reporting methods each inspect both datasets without changing any outcomes.

## Setup and exact reproduction

Python3.10+ standard library, no dependencies or installation. From this directory:

```sh
python3 -B experiment.py
python3 -B -m unittest -v
python3 -B test_experiment.py --validate
```

The first command overwrites artifacts/run.json and evidence.md; the last overwrites artifacts/checks.json and runs two deliberately faulty copies in automatically removed temporary directories. No external service or credential is needed.

## Exact results

These are invented outcome records. No agent or note operation ran. The two reporting methods do not change any outcomes.

Both invented datasets have two task completions and two malicious completions out of four. Pairing determines how many task completions had no tested malicious result.

| Dataset | n | Task total | Malicious total | Task only | Both | Malicious only | Neither |
|---|---:|---:|---:|---:|---:|---:|---:|
| A: separate |4|2|2|2|0|2|0|
| B: together |4|2|2|0|2|0|2|

The same totals permit a task-only count from0 through2. The paired report identifies2 for A and0 for B. It does not improve either dataset or block any action. The benign twin has4 task-only records. The neither-completed twin has0 malicious outcomes and0 task completions. Neither completion is not proof of refusal.

Inspect [every input and computed count](artifacts/run.json), [all scenario counts](evidence.md), and [validation and deliberate-fault evidence](artifacts/checks.json).

## Oracle and validation

With n records, B task successes and A malicious successes, let x be the number where both succeed. The desired task-only count is B-x. Feasible overlap satisfies max(0,A+B-n) <= x <= min(A,B), hence:

```text
max(0,B-A) <= task_only <= min(B,n-A)
```

No independence assumption is required. Nine focused tests cover all four cells, asymmetric cases, missing observations, exact Boolean types, identity/shape validation, empty inputs, ordering and input preservation. Independent tuple enumeration checks every paired sequence of lengths0 through6, comparing observed feasible ranges with the formula. These are finite code checks, not empirical agent trials. Deliberate faults switch the intersection and treat missing observations as false; both must cause assertion failures without test errors.

## Limits and engineering check

- This does not measure attack prevalence, model ability, defense efficacy, statistical uncertainty, recovery or any untested harm. A task-only record is favorable only for the two specified objectives; it is not universally safe.
- Supplied labels can be wrong or omit harms. The program cannot validate semantic truth, provenance or completeness beyond its strict record shape and duplicate IDs. A fabricated complete-looking input can pass.
- Missing labels reject the dataset instead of silently becoming false. This simple audit does not provide partial-cohort estimation. Empty input has denominator0 and no rate.
- Counts require paired outcomes from the same runs and population. Do not combine unmatched cohorts or rounded published marginal percentages and claim an exact observed joint result.
- Every record is equally weighted. Stratification, macro-averages, adaptive sampling and live-model variation are outside this calculation. Repeating deterministic fixtures adds no empirical evidence.
- This is distinct from checking only a final deliverable: both task and malicious totals are already known here. The missing information is which outcomes occurred together.

For agent evaluations, retain the requested-task and tested malicious-objective result under the same run ID, then publish all four joint counts beside their totals. Add a regression fixture with equal totals but different pairings, and keep unknown results separate from observed failures. This checks reporting, not runtime protection.
