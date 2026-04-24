# Assignment 06 — AI Agent Security Integration

Integrates security guardrails into the Assignment 05 research paper pipeline agent, protecting it against prompt injection, API abuse, and harmful content.

## Quick Start

```bash
cd submit
pip install python-dotenv openai
python demo.py
```

## Architecture

| Class | Responsibility |
|-------|---------------|
| `InputValidator` | Validates length, word count, HTML sanitisation, prompt injection patterns |
| `RateLimiter` | Sliding-window rate limiting (default: 10 req/min per session/IP) |
| `EthicalGuard` | Blocks harmful content across 5 categories: Violence, Discrimination, Sexual, Criminal, SelfHarm |
| `SecurityContext` | Bundles `session_id` + `ip` for all modules |
| `@with_security` | Decorator wiring all checks together in a reusable pipeline |

## Integration with Dashboard (Assignment 05)

```python
from submit.security import with_security

# Wrap the existing process function
secure_process = with_security(process)

# In app.py — pass session_id from Streamlit
result = secure_process(topic, session_id=st.session_state.get("session_id"))
```

## Module Details

### InputValidator

```python
validator = InputValidator(max_length=1000, max_words=200)
ok, msg = validator.validate("your research topic here")
# ok=True → proceed, ok=False → use msg as error reason

clean = validator.sanitize("<script>alert('xss')</script>user input")
# Removes HTML injection tags
```

### RateLimiter

```python
limiter = RateLimiter(max_requests=10, window_seconds=60)
ok, msg = limiter.check(session_id)
# ok=True → allowed, ok=False → msg contains wait time

remaining = limiter.get_remaining(session_id)
limiter.reset(session_id)  # admin use
```

### EthicalGuard

```python
guard = EthicalGuard()
ok, msg = guard.check_input(user_text)   # before model call
ok, msg = guard.check_output(model_output)  # after model call
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MOONSHOT_API_KEY` | Moonshot AI API key (used by `demo.py`; real app uses its own config) |

## Limitations

- **Rate limiting**: In-memory store — not shared across multiple processes or server instances. For production, replace `_rate_limiter_store` with a Redis backend.
- **Ethical guard**: Keyword-based detection only. Does not defend against adversarial paraphrasing. For production, consider an LLM-based classifier.
- **Prompt injection**: Regex-based. Sophisticated attackers can use Unicode lookalikes or encoding tricks.

## Running Tests

```bash
cd 06
pip install pytest
python -m pytest test/test_security.py -v
```
