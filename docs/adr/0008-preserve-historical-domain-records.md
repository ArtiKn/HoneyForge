# Preserve historical domain records

Traps and previously assigned Trap Profiles are archived rather than physically deleted, and Security Events, Attack Sessions, and audit entries remain immutable until their retention cleanup. This consumes more storage than cascading deletion but preserves the configuration and identity context needed to interpret historical attack data.


## Amendment: explicit permanent deletion

At the Operator's explicit request, DELETE now permanently removes a Trap with its
Security Events, Attack Sessions, credentials, and entity audit entries. Archiving
remains available as a separate action. Trap Profiles are physically deleted only
when no Trap references them; assigned profiles return 409 and must first be
reassigned or have their Traps explicitly deleted. This avoids an implicit cascade
from a reusable configuration to deployed Traps. Archived profiles can be deleted
under the same rule. Entity audit entries are removed with the deleted entity.
