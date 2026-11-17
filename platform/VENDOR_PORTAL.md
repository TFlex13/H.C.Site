# Highline Connect: Vendor portal and catalog (Phase 1)

## Purpose

Vendors have their own role-based login and can submit catalog items and wholesale-price/commission proposals. Administrators approve or reject proposals and allocate the total proposed service fee between Highline and the representative. Approved products are visible in the representative Sales Catalog. There is **no automatic payable order or checkout** in this phase.

## Apply migration

From `C:\Users\Staff\medusa-projects\highline-connect\platform`, after the previous migrations through 019:

```powershell
$output = Get-Content .\migrations\020_vendor_portal_catalog.sql -Raw |
  docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1 2>&1
$exitCode = $LASTEXITCODE
$output
if ($output) { $output | Out-String | Set-Clipboard }
if ($exitCode -ne 0) { throw "Vendor catalog migration failed" }
```

Migration 020 changes the allowed `users.role` values to include `vendor`, and adds separate vendor memberships, invitations, products, catalog-offer revisions, and audit records. It is additive to vendor agreements and commission orders; old orders and financial snapshots are unchanged. Do not rerun a successfully committed migration.

## Test flow

1. Log into the admin dashboard on `http://127.0.0.1:3002/admin/dashboard`, then select **Vendors**.
2. Create a vendor name, or select an existing active vendor. Enter the vendor contact email and generate a setup link. No automatic email is sent. Copy it from the admin screen.
3. Open the full URL in a fresh tab at `/vendor/signup#token=...`. Set a password of at least 12 characters and a display name. The token expires after 48 hours and can be accepted only once.
4. Sign in via `/vendor/dashboard` with that vendor's email and password.
5. Create a test SKU, name, optional category/description, unit label, wholesale sale price, vendor unit cost, and offered service-fee percentage of **vendor gross profit**.
6. Return to Admin > Vendors. Under **Product commission proposals**, review the product and split the offered service fee percentage between Highline and the rep. Example: sale $20, cost $12, gross profit $8, offered fee 20% of profit = $1.60; Highline 12% of profit = $0.96, rep 8% = $0.64. The two percentage points must sum to the vendor's offered rate.
7. Approve the proposal. Log in as an approved rep, refresh their dashboard, and inspect **Sales Catalog**. The SKU and approved wholesale price should appear, but the vendor's unit cost stays confidential.
8. Propose a new price/commission revision in the vendor portal and verify that the old approved offer remains active until admin approval.

## Known boundaries

- This catalog is not yet connected to the commission-orders ingestion route. Existing vendor commission agreements govern existing orders and cannot be overwritten by these catalog proposals. Integrating product-specific approval snapshots into orders requires an explicit subsequent migration and pricing/line-item design.
- Vendor offerings and licenses may have product or jurisdiction restrictions. Restricted categories need approval gates before the catalog is used commercially.
- Authentication and authorization rely on the existing session system; vendor roles can only read and edit their own vendor's products. Admin endpoints enforce admin-only access.
- Catalog entries use text only in this phase. Product images, bulk CSV uploads, inventory, per-store pricing, tax and shipping, ordering, vendor fulfillment, and inventory availability are deferred.
- Vendor cost is private to the vendor and Highline administrators; rep catalog responses exclude vendor cost.
- Do not use real sensitive vendor financial data during initial local testing.
