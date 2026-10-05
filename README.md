# AEGISAI — Red-Team AI. Break It Safely. Defend It Automatically.
Hack in Hills '26 · PS-04 Securing Adversarial AI Testing

Adversarial AI test lab: attack gateway → rule-based security engine → sandboxed demo agent → tool gateway → SHA-256 hash-chained audit ledger.

## Run
    docker compose up --build      # http://localhost:8000
    # or without Docker
    cd backend && pip install -r requirements.txt && uvicorn app:app --reload

Demo logins (password `aegis123`): admin@aegis.ai · redteam@aegis.ai · blueteam@aegis.ai

## Security model
- JWT auth + RBAC: red team can attack but cannot read the audit ledger; blue team can read/verify the ledger but cannot execute attacks; red can only read its own team's attacks (workspace-scoped).
- Hash-chained audit log (SHA-256, each record includes previous hash); verify endpoint recomputes the chain; admin "tamper" button shows detection.
- Tool gateway: identity → permission → risk → policy → allow/deny → audit.
- Container: non-root user, no-new-privileges, all capabilities dropped.

## Residual risk (honest)
Regex rules are bypassable (paraphrase, encoding, multilingual). Agent is simulated ("Demo AI Engine"), not a real LLM. Isolation is logical (RBAC), not hardware/network. Hash chain is tamper-evident, not tamper-proof (a DB admin can recompute it; anchor hashes externally). Demo password and default JWT secret must be changed. No guarantee against future attacks.

## API
POST /api/auth/login · GET /api/dashboard · POST /api/attacks/execute · GET /api/attacks · GET /api/attacks/{id} · POST /api/attacks/{id}/replay · POST /api/demo/run · POST /api/tools/check · GET /api/audit · POST /api/audit/verify · GET /api/threats · GET /api/analytics · GET /api/agents · GET /api/tools
Docs: /docs (Swagger)
