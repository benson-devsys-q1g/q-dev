# NQ-B1 Identity Qualification

- Date (UTC): 2026-11-16
- Purpose: Personal fixture check that one bounded cloud session can create a single branch, commit one nonsecret file, push, and open one draft PR against `main` in this repository.
- Scope: This file only. No other files, settings, or branches are changed. The PR is a draft and must not be merged.

## Caveat

The git commit author is configurable and is not proof of identity. The GitHub API actor that created the branch, commit push, and pull request must be verified independently (for example, via the PR's author and the repository events/audit data on GitHub).
