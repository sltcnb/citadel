# Contributor Covenant Code of Conduct

## Our pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of age, body
size, visible or invisible disability, ethnicity, sex characteristics, gender
identity and expression, level of experience, education, socio-economic status,
nationality, personal appearance, race, caste, colour, religion, or sexual
identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming,
diverse, inclusive, and healthy community.

## Our standards

Examples of behaviour that contributes to a positive environment:

- Demonstrating empathy and kindness toward other people.
- Being respectful of differing opinions, viewpoints, and experiences.
- Giving and gracefully accepting constructive feedback.
- Accepting responsibility and apologising to those affected by our mistakes,
  and learning from the experience.
- Focusing on what is best not just for us as individuals, but for the overall
  community.

Examples of unacceptable behaviour:

- The use of sexualised language or imagery, and sexual attention or advances of
  any kind.
- Trolling, insulting or derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information, such as a physical or email address,
  without their explicit permission.
- Other conduct which could reasonably be considered inappropriate in a
  professional setting.

## Handling evidence and sensitive data

Citadel is digital-forensics tooling. Contributions routinely touch material that
belongs to someone else — often a victim of an intrusion. That places obligations
on this project that a general code of conduct does not cover, and they are not
optional:

- **Never commit real evidence.** No host artifacts, memory images, disk images,
  event logs, packet captures, browser history, mailboxes, or credentials — not
  in tests, not in fixtures, not in an issue attachment, not "temporarily".
  Test data must be synthetic, or a published sample from a source that licenses
  it for redistribution. Synthesise fixtures from a format specification instead
  (see `tools/sluice/worker/collection_inventory.py` for examples).
- **Never commit case data or identifiers.** Real hostnames, usernames,
  internal IP ranges, case numbers, client names, and ticket references are
  someone's incident, not a convenient example. Use documentation-reserved values
  (RFC 5737 addresses, `example.com`, obviously fictional names).
- **Redact before you report.** When a bug reproduces only on real evidence,
  describe the *structure* that triggers it — record layout, field values, byte
  offsets, sizes — and attach a synthetic file that reproduces it. Never attach
  the original.
- **Respect the confidentiality of what tooling reveals.** If reviewing a PR,
  reading a bug report, or testing a change exposes you to another party's data,
  do not retain, share, or act on it.
- **Dual-use knowledge is discussed for defence.** Detection logic, parsers, and
  analysis modules necessarily encode how attacks work. Discussing attacker
  technique to build detection or explain an artifact is the work. Using this
  project — its issues, discussions, or code — to solicit help attacking systems
  you are not authorised to test is not, and is treated as a violation.

If you realise you have committed sensitive material, say so immediately rather
than quietly force-pushing over it. Git retains history, forks retain copies, and
mirrors may already have fetched it: the maintainers need to know so the exposure
can actually be addressed.

## Enforcement responsibilities

Project maintainers are responsible for clarifying and enforcing these standards
and will take appropriate and fair corrective action in response to any behaviour
they deem inappropriate, threatening, offensive, or harmful.

Maintainers have the right and responsibility to remove, edit, or reject
comments, commits, code, issues, and other contributions that are not aligned to
this Code of Conduct, and will communicate reasons for moderation decisions when
appropriate.

## Scope

This Code of Conduct applies within all community spaces — the repository, its
issues, pull requests, discussions, and any project communication channel — and
also applies when an individual is officially representing the community in
public spaces.

## Reporting

Report abusive, harassing, or otherwise unacceptable behaviour through either of
the following, matching the private channels described in
[`SECURITY.md`](SECURITY.md):

- Contact the maintainers privately via the
  [repository owner's profile](https://github.com/sltcnb).
- For conduct that violates GitHub's own terms, use GitHub's
  [report abuse](https://github.com/contact/report-abuse) form, which reaches
  GitHub's Trust & Safety team independently of this project.

Reports involving exposure of real evidence or case data should go through the
[Security Advisory](https://github.com/sltcnb/citadel/security/advisories/new)
channel instead, so the disclosure stays private while it is remediated.

All complaints will be reviewed and investigated promptly and fairly. Maintainers
are obligated to respect the privacy and security of the reporter of any
incident.

## Enforcement guidelines

Maintainers will follow these Community Impact Guidelines in determining the
consequences for any action they deem in violation of this Code of Conduct:

### 1. Correction

**Community impact:** Use of inappropriate language or other behaviour deemed
unprofessional or unwelcome.

**Consequence:** A private, written warning from maintainers, providing clarity
around the nature of the violation and an explanation of why the behaviour was
inappropriate. A public apology may be requested.

### 2. Warning

**Community impact:** A violation through a single incident or series of actions.

**Consequence:** A warning with consequences for continued behaviour. No
interaction with the people involved, including unsolicited interaction with
those enforcing the Code of Conduct, for a specified period of time. This
includes avoiding interactions in community spaces as well as external channels
like social media. Violating these terms may lead to a temporary or permanent ban.

### 3. Temporary ban

**Community impact:** A serious violation of community standards, including
sustained inappropriate behaviour.

**Consequence:** A temporary ban from any sort of interaction or public
communication with the community for a specified period of time. No public or
private interaction with the people involved, including unsolicited interaction
with those enforcing the Code of Conduct, is allowed during this period.
Violating these terms may lead to a permanent ban.

### 4. Permanent ban

**Community impact:** Demonstrating a pattern of violation of community
standards, including sustained inappropriate behaviour, harassment of an
individual, or aggression toward or disparagement of classes of individuals.
Deliberately publishing another party's evidence or case data is treated at this
level.

**Consequence:** A permanent ban from any sort of public interaction within the
community.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage],
version 2.1, available at
https://www.contributor-covenant.org/version/2/1/code_of_conduct.html.

Community Impact Guidelines were inspired by
[Mozilla's code of conduct enforcement ladder][mozilla].

The "Handling evidence and sensitive data" section is specific to this project
and is not part of the Contributor Covenant.

For answers to common questions about this code of conduct, see the FAQ at
https://www.contributor-covenant.org/faq. Translations are available at
https://www.contributor-covenant.org/translations.

[homepage]: https://www.contributor-covenant.org
[mozilla]: https://github.com/mozilla/diversity
