# Domain Docs

HoneyForge is a single-context repository. Engineering skills must read and respect its domain documentation before exploring or changing the relevant area.

## Before exploring

- Read the root `GLOSSARY.md` and use its canonical terms in issues, specifications, tests, and code.
- Read the relevant decisions under `docs/adr/`.
- If either location is absent, proceed without proposing placeholder documentation.

## Rules

- Do not drift to synonyms that `GLOSSARY.md` explicitly marks as avoided.
- If a required domain concept is missing, note the gap for domain modeling rather than silently inventing competing language.
- Surface any conflict with an ADR explicitly instead of silently overriding the recorded decision.

## Layout

```text
/
├── GLOSSARY.md
└── docs/
    └── adr/
```
