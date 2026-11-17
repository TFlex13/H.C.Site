# Store Onboarding (Local Development)

This is a manual-email, administrator-reviewed first version. Do not expose the local API to the public internet. No automated email delivery is configured.

## Migration

After applying migrations 001-016, run from `platform` (PowerShell):

```powershell
Get-Content .\migrations\017_store_onboarding.sql -Raw |
  docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1
if ($LASTEXITCODE -ne 0) { throw "Store onboarding migration failed" }
```

This migration creates invitations, applications, encrypted document references, and audit history. It does not delete or modify existing stores.

## Local flow

1. Start the existing API at `http://127.0.0.1:3002` with `HIGHLINE_DOCUMENT_ENCRYPTION_KEY` and `HIGHLINE_PRIVATE_DOCUMENT_DIR` already configured and backed up.
2. Sign in as an approved representative at `/representative/dashboard`. Under **My stores**, enter a store email and generate a link. **The email is not sent automatically.** Copy the complete URL and send it manually in a trusted channel.
3. Open the link as the store contact. It expires after 7 days. Complete business details, optionally enter the EIN (encrypted at rest), and upload EIN confirmation letter and applicable licenses (PDF/JPG/PNG, max 10 MB each). Every license needs an expiration date; EIN letters do not.
4. Click **Submit for review**. Submitting a store application does not authorize it to transact.
5. Sign in as admin at `/admin/store-onboarding/dashboard`, linked from the Stores section of `/admin/dashboard`. Review documents; click **View** before verifying or rejecting; rejection reasons are required. Approve only when business-specific licensing is sufficient.
6. Approval automatically assigns the store to the representative who generated its invitation. On the first approval, the application creates a representative-specific store portfolio territory, then reuses that portfolio for future approved stores. Administrators no longer select a territory for each application. The representative must still be active and approved.
7. Refresh the representative dashboard. The approved and assigned store should appear under **My stores**.

## Representative portfolio migration (new)

After migrations 017 and 018, run `019_representative_store_portfolios.sql` before testing automatic store approval:

```powershell
Get-Content .\migrations\019_representative_store_portfolios.sql -Raw |
  docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1
if ($LASTEXITCODE -ne 0) { throw "Representative store portfolio migration failed" }
```

This creates only a representative-to-portfolio mapping table. It does not move previously assigned stores, rename existing geographic territories, or create geographic exclusivity. Existing geographic territory assignments remain available for future policy work.

## Security and deferred work

- Invitation tokens are 256-bit random values, SHA-256 hashed in the database, carried in the URL fragment, and expire after 7 days. Anyone with the unexpired link can complete its application. Do not send links to unauthorized parties.
- Uploaded documents use the same private AES-256-GCM key and directory as representative uploads, with separate document records. Keep the encryption key private and backed up. Full EIN is encrypted; only its last 4 digits are shown to administrators.
- Applicant document status and audit history are stored. Rejected license replacement can be resubmitted; older rejected evidence is marked superseded.
- Licenses vary by jurisdiction and product category. This version does **not** determine legally required permits, validate tax IDs with an authority, verify authenticity, or implement automated expiration suspension/sales locks. Administrators must manually determine required documents.
- Implement delivery service, invite revocation/reissue, email verification, additional abuse controls, document retention/deletion, automatic license renewal, expiration enforcement, jurisdiction-specific requirements and production-grade security testing before launch.
- Never use real customer tax IDs or private licenses in publicly exposed development environments.
