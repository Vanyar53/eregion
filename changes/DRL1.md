### Added
- **The weekly bench drill, designed: one exercise a week, played by a timer on Orodruin** (DRL1, #613; `docs/design/drill-banc.md`, indexed in `CLAUDE.md`). Jonathan's decision of 06/11, so that the age of the last proof (under 30 days) holds by itself. The design covers:
  - **The content.** A shipped drill, `drills/banc-hebdo.yaml`, with two new blocks: `schedule` (shipped drills only, every wire in zone `bench`, techniques implemented, non-destructive, from a public library) and `expect` (the rule the watch should fire, within a delay). Version 1 holds one wire: T1136.001, the pinned Atomic Red Team test already proven from Orodruin.
  - **The timer.** A systemd timer, installed disabled and armed by the operator. It reads only the verified image, the arming file and the clock. The drill's digest is pinned at arming. It runs in zone `bench` only, at most once in six days, never caught up, and never again after an emergency stop until re-armed. It goes through the same judge as a Dagorlad request.
  - **The report.** Each occurrence is judged on H0, which also raises the alarm when nothing arrived. The Banc session reads the workspace as an independent witness.
  - **The rest.** The cost (how Orodruin is powered on), the threat model frontier it adds (proposed, not yet written there), and what VP1 reads.
  - No code, no change of behaviour.
