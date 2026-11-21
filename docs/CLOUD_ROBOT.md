# SmartSub Cloud Robot

SmartSub Actions acts as a cloud-side candidate collector and strict node-admission runner.

## Admission flow
1. Existing collectors and the legacy quality filter discover candidates and perform initial TCP/latency/risk screening.
2. scripts/cloud_robot.py parses up to 20 candidates, ordered US first, Europe second, Asia third.
3. Each candidate is isolated in its own Mihomo process and tested through that proxy.
4. ChatGPT, Gemini, and Roblox probes are recorded independently.
5. A node is provisional after one complete passing run and formal after three consecutive UTC-day passing runs. Any failed or unknown app probe resets its streak to zero.
6. test_nodes.yaml and test_nodes.txt contain formal nodes only. Provisional candidates are published separately for evaluation.

## Persistent state
state/cloud_robot_state.json stores SHA-256 node fingerprints, country/protocol labels, streaks, dates, and per-app outcomes. It does not store raw proxy URIs, UUIDs, passwords, or other credentials. The state is committed with each successful workflow run.

## Probe semantics
- TCP reachability and initial latency are candidate prefilters, not admission evidence.
- Mihomo must start and pass a Google connectivity bootstrap through the candidate.
- ChatGPT accepts HTTP 200/301/302/401; 401 means the unauthenticated endpoint is reachable. 403 and transport errors fail.
- Gemini and Roblox accept HTTP 200/301/302. Other statuses and timeouts fail.
- Formal publication requires all three apps to pass on three consecutive UTC dates. Re-running on the same UTC date does not increase the streak.

## Operating boundary
GitHub-hosted runners test from their own network locations. Results describe reachability from that runner through the tested proxy, not a guarantee of long-term availability or the user's local ISP path. These are point-in-time probes; a geographically distributed probe matrix can be added later.

## Tests
Run: python -m unittest discover -s tests -p "test_cloud_robot.py"
