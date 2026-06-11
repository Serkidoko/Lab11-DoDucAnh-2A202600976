# HITL Flowchart

```mermaid
flowchart TD
    A["User request"] --> B["Rate limiter"]
    B -->|Too many requests| H1["Human-on-the-loop review: abuse monitoring"]
    B -->|Allowed| C["Input guardrails"]
    C -->|Prompt injection or secret request| H2["Human-on-the-loop review: safety anomaly"]
    C -->|Safe banking input| D["Banking assistant"]
    D --> E["Output guardrails"]
    E -->|PII or secret redacted| F["LLM-as-Judge"]
    E -->|Clean output| F
    F -->|Fail or low confidence| H3["Human-as-tiebreaker"]
    F -->|Pass| G{"High-risk action?"}
    G -->|Transfer, account closure, password change| H4["Human-in-the-loop approval"]
    G -->|General support| I["Send response"]
    H1 --> J["Audit log and monitoring"]
    H2 --> J
    H3 --> J
    H4 --> J
    I --> J
```

## Decision Points

| # | Decision point | Trigger | HITL model | Reviewer context |
|---|---|---|---|---|
| 1 | High-value money movement | Large transfer, beneficiary change, account closure, or password change | Human-in-the-loop | Identity checks, amount, recipient, device risk, recent activity |
| 2 | Identity or account recovery ambiguity | Medium/low confidence on password reset, phone change, KYC update, or account unlock | Human-as-tiebreaker | Verification attempts, KYC profile, confidence score, support history |
| 3 | Safety or compliance anomaly | Prompt injection, secret request, repeated blocks, or suspicious session pattern | Human-on-the-loop | Original prompt, matched rules, sanitized response, session risk score |
