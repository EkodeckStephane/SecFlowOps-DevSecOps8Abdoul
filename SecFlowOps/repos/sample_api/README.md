# sample_api

Small Python HTTP API used for SecFlowOps controlled scanner runs.

Intentional issues:

- reflected output pattern in `app.py`;
- vulnerable dependency pin in `requirements.txt`;
- fake test secret in `.env.test`;
- Dockerfile and Kubernetes hardening issues.

All secrets are fake and invalid.
