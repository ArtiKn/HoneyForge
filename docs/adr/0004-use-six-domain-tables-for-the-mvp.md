# Use six domain tables for the MVP

The MVP schema uses `trap_profiles`, `traps`, `security_events`, `attack_sessions`, `operators`, and `audit_entries`, matching the canonical domain language instead of preserving the scaffold's `honeypot` names. The premature `honeytokens` table is removed and will be introduced by a later migration only if that Bonus feature is implemented, resolving the work plan's contradiction between its six-table claim and seven-table draft structure.
