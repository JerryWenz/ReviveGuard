# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
private vulnerability reporting ("Security" tab → "Report a vulnerability") for
this repository. Include the affected version, steps to reproduce and the
impact. Reports are handled on a best-effort basis; no response-time guarantee
is made at this stage of the project.

## Scope

ReviveGuard is a local host auditing tool. Of particular interest:
- any way to make it modify the system in `audit` mode;
- command or path injection through configuration or system data;
- leaking secrets into logs or reports;
- remediation that could lock an administrator out.

## Status

The project is in early development and has not been security-reviewed. Do not
rely on it for production decisions yet.
