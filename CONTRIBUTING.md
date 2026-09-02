# Contributing to VECTPHISH

Thank you for considering a contribution.

## Development workflow

1. Fork the repository
2. Create a feature branch
3. Install development dependencies
4. Run linting and tests
5. Submit a pull request

```bash
pip install -e ".[dev]"
pre-commit install
ruff check .
black --check .
pytest
```

## Contribution areas

- Additional IOC extraction logic
- Dashboard improvements
- Additional ATT&CK mappings
- Threat intelligence feed integrations
- Documentation improvements
- Test coverage

## Design principles

- Keep the tool lightweight
- Avoid mandatory cloud dependencies
- Support offline and air-gapped operation
- Keep analyst review in the loop
- Make detection logic explainable
