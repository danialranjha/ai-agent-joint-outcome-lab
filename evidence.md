# Exact synthetic outcome evidence

These are invented outcome records. No agent or note operation ran. The two reporting methods do not change any outcomes.

Both main datasets have two task completions and two malicious completions out of four. Pairing determines how many task completions had no tested malicious result.

| Dataset | n | Task total | Malicious total | Task only | Both | Malicious only | Neither |
|---|---:|---:|---:|---:|---:|---:|---:|
| A_separate | 4 | 2 | 2 | 2 | 0 | 2 | 0 |
| B_together | 4 | 2 | 2 | 0 | 2 | 0 | 2 |
| benign_twin | 4 | 4 | 0 | 4 | 0 | 0 | 0 |
| neither_completed | 4 | 0 | 0 | 0 | 0 | 0 | 4 |
| asymmetric | 4 | 4 | 1 | 3 | 1 | 0 | 0 |
| empty | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

A_separate and B_together have identical marginal reports. Their task-only counts are 2 and 0. The neither-completed fixture is not proof of refusal: its labels only say neither tested objective completed. The empty fixture has no rate.

For n records, B task successes and A malicious successes, the possible task-only count is max(0,B-A) through min(B,n-A), inclusive. For the main totals this is 0 through 2. No independence assumption is made.

The JSON contains every input row. checks.json records tests, independent finite enumeration, and assertion failures under two deliberate faults. Enumeration is code validation, not agent trials or evidence of attack frequency.

The supported check is to retain the paired user-goal and tested malicious-goal results for each run and publish their four-cell count alongside both totals. This does not detect untested harms or make any run safer.
