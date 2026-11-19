# Store registration credentials during onboarding

New behavior applies after migration **022_store_registration_credentials.sql**.

1. Representative creates the standard store onboarding invitation.
2. Store saves its business information and uploads supporting documents.
3. Before the first submission for review, the store creates and confirms a password (minimum 12 characters). The password is processed with the application's scrypt password hasher and never appears in the admin UI or the API response.
4. The application creates a **disabled** `users` record for the invited email and associates its ID with the pending application, within the same database transaction as submission. Disabled accounts cannot log in.
5. If admin requests changes, the application uses the already-stored inactive credentials without asking for the password again.
6. On approval, the system creates the store and its representative assignment as before, links the pending user to that store via `store_memberships`, and enables login atomically. The store can then sign in directly at `/store/dashboard`.
7. Rejected applications leave their inactive login reserved; account recovery, email changes and a reapplication workflow require later work.

Existing approved store records and their activated user accounts remain unchanged. **For approved stores registered before this feature, the manual Admin > Stores > Activate a store shopping account flow remains available**.

## Apply after migration 021

From `platform`:

```powershell
$output = Get-Content .\migrations\022_store_registration_credentials.sql -Raw |
  docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1 2>&1
$exitCode = $LASTEXITCODE
$output
if ($output) { $output | Out-String | Set-Clipboard }
if ($exitCode -ne 0) { throw "Store registration credentials migration failed" }
```

This only adds a nullable application-to-login reference. It does not overwrite any existing password, store, or membership.

## Follow-up hardening

- Production store account creation should verify ownership of the invited email, rather than relying solely on access to the forwarded invitation URL.
- Provide secure store password reset, credential changes and account recovery.
- Add PostgreSQL-backed end-to-end tests covering draft submission, rejection/changes, approval, idempotency, and member isolation.
