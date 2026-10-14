# Do not masquerade the Agent process

HoneyForge interprets the process-hiding requirement as protecting credentials and isolating management components from the attack surface, not impersonating an operating-system service. The Agent runs without root as the honestly named `honeyforge-agent`; the scaffold's `syslog-relay` disguise is removed because it misleads administrators and offers no security boundary.
