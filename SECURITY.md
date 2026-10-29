# Security policy

Eregion acts on cloud infrastructure: Glorfindel can isolate a VM and block an address, Annatar and Gothmog run real attacks and faults on enrolled targets. A flaw in it can matter. Thank you for taking the time to report one.

## Supported versions

Eregion is before 1.0, maintained by one person. Fixes go into the **latest 0.4.x release** (and `main`); an older release is not patched — upgrade to the latest one. The versions and what changed: [`CHANGELOG.md`](CHANGELOG.md).

| Version | Supported |
|---|---|
| latest 0.4.x | yes |
| older 0.4.x, 0.3.x and before | no — upgrade |

## How to report a vulnerability

**Privately, through GitHub**: the repository's **Security** tab → **Report a vulnerability** (a private security advisory). Only the maintainer sees it.

If the button does not show, open an issue that asks for a private contact — **with no detail of the flaw** (no component, no steps, no impact); the maintainer answers with a private channel.

Please do **not** describe a vulnerability in a public issue or pull request, nor in a public channel. There is no security e-mail address.

What helps:
- the version or commit, and how Eregion runs (Docker Compose, a local install, the hosted profile);
- what an attacker needs beforehand (a log line they can write on a watched VM, a Discord account on the server, a pull request from a fork, a local account on the host…) and what they get;
- the steps to reproduce, on your own deployment, and what you expected instead.

## What happens next

Indicative delays — one maintainer, best effort:
- **acknowledgement** within 7 days;
- **a first assessment** (accepted or not, the severity) within 14 days;
- **a fix**: within 30 days for a high or critical flaw, in the next release for the others; you are told the plan if it takes longer.

The fix is released first, then the advisory is published, crediting you if you wish. Until then, please keep the details private. Changelogs and commits describe the fix, not how to exploit it.

## Scope

**In scope**: the code of this repository — Glorfindel (`glorfindel/`), the console (`eregion_console/`), the shared core (`eregion_core/`), the analysis (`analysis/`), Annatar (`annatar/`), Gothmog (`gothmog/`), the Terraform modules (`infra/`), the scripts, the Docker and Compose files, the GitHub workflows. Test it on **your own deployment**.

In particular, a way around a guard is a vulnerability: an action that runs where the asset's mode, the destructive gate, the confidence gate or `never_block` should have held it; an injector acting outside an armed Orodruin, on a target not enrolled, or without a live Glorfindel watch; the console answering without its token, or under another host or origin; text from outside (a log line, a name in Azure, the model's answer) executed or rendered as markup in the console or a chat.

**Out of scope**:
- the maintainer's own bench, hosted instance, injectors' host, Azure subscription and Discord server — please do not test them;
- a flaw in a dependency (report it upstream; tell us if the way Eregion uses it makes it worse). A published advisory on a locked version is already tracked: a weekly audit opens an issue labelled `security` for it (CI2);
- what needs the operator's own rights already: root on the host, the console's token, the cloud credentials Eregion runs with.

## What is not a vulnerability

- **Nothing runs by default.** `human_only` is the default mode: every action is a recommendation a human approves. It is the design, not a missing feature.
- **Observation.** Glorfindel recommending without acting, `GLORFINDEL_READ_ONLY=1`, and the cards it writes then, are by design.
- **The model being wrong.** A wrong or overconfident recommendation is expected; safety never rests on the model's confidence. It is a vulnerability only when a guard lets it run where it should not (above).
- **Annatar and Gothmog attacking.** They run real attacks and faults, on purpose, on enrolled targets, from an armed Orodruin, never without Glorfindel.
- **The open points of the threat model.** [`docs/design/modele-de-menace.md`](docs/design/modele-de-menace.md) (in French) lists, for each boundary, what holds and what is still open and planned. A report that goes further than what is described there is welcome.
