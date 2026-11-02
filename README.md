# Prompt Hygiene

Local, explainable checks for common sensitive-text patterns before a prompt or document is shared with an AI tool.

It scans on your machine and writes a redacted JSON review report. No text is uploaded by this package. Findings include approximate emails, telephone-like numbers, API-key-like tokens, private-key headers and password assignments.

## Use

```bash
pip install .
prompt-hygiene --text "Please summarise this. password=example-secret" --output report.json
```

The command returns exit code `2` when high-severity patterns are found, which makes it suitable as an optional pre-commit or CI check.

## Important limits

This is a heuristic checker, not a data-loss-prevention product or a guarantee that text is safe to share. It can miss data, flag harmless content and does not replace organisational policy, consent or human review.

## Development

```bash
pip install ".[dev]"
pytest -q
```

## License

MIT
