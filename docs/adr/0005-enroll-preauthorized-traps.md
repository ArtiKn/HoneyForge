# Enroll preauthorized Traps

An Operator pre-creates each Trap and issues a hashed, single-use Enrollment Token that expires after ten minutes; the Agent exchanges it for a unique Trap Secret whose hash is retained by the Control Center. This rejects unauthenticated self-registration and fleet-wide shared secrets while deferring the operational complexity of mTLS to a Bonus phase. Rotation allows a five-minute overlap, while revocation invalidates every credential immediately.
