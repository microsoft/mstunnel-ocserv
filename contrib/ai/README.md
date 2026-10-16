# AI Assistance Framework

This directory contains persona files for use with AI coding agents working on ocserv.
See [`AGENTS.md`](../../AGENTS.md) in the repository root for the full agent guide.

## Personas

| File | Intended for |
|------|-------------|
| `personas/ocserv-core-dev.md` | Maintainers: bug investigation, code review, design, release |
| `personas/ocserv-contributor.md` | External contributors: features, bug fixes, security fixes |

Load the appropriate file as a system prompt prefix in your AI tool before starting work.

## Acknowledgment

The structure of this framework — composable persona and protocol files that can be
combined into reliable, repeatable AI prompts — is inspired by
[PromptKit](https://github.com/microsoft/PromptKit) by Microsoft. The protocol names
(anti-hallucination, memory-safety, security-vulnerability, self-verification) follow
PromptKit's vocabulary. All content is written specifically for ocserv and its codebase.
