# Security policy

Report vulnerabilities through the repository's private security advisory
channel. Do not open public issues containing credentials, tokens, customer
data, SIP secrets, or infrastructure access details.

Secrets must be delivered through protected runtime mounts and must never be
committed. Pull requests must pass secret scanning, dependency review, tests,
and container scanning before release approval.
