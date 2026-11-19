# Store shopping and representative order requests (Phase 1)

## What was added

- Representative workspace: "Place an order request for a store" with a store selector restricted to the signed-in representative's active assigned stores, approved vendor catalog, request cart and submitted request history.
- Store workspace: /store/dashboard, with approved vendor catalog, request cart and order request history. Store signup uses a separate, one-time, 48-hour account invitation at /store/account#token=..., issued by an administrator to the email already recorded on an approved, active store.
- Admin > Stores: issue store-account invitations, copy the secure link for manual delivery, view incoming order requests (read-only).
- The existing authenticated session system now accepts the store role and ties each store user to exactly one approved store via store_memberships.
- Catalog order requests preserve exact approved product offer IDs, unit wholesale prices, quantities, and request totals in database snapshots. They **do not** create commission_orders, charge money, reserve inventory, contact vendors, or fulfill shipments.

## Local database migration 021

Apply only after 020, and do not rerun a committed migration. From platform in PowerShell:

```powershell
$output = Get-Content .\migrations\021_store_accounts_order_requests.sql -Raw |
  docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1 2>&1
$exitCode = $LASTEXITCODE
$output
if ($output) { $output | Out-String | Set-Clipboard }
if ($exitCode -ne 0) { throw "Store shopping migration failed" }
```

This adds a store role and four tables for account membership, invitations, order requests and request items. It leaves approved store assignments and all existing financial transactions unchanged.

## Testing

1. Use a fictional approved store with a contact email in Admin > Stores > Store Directory. Select it under **Activate a store shopping account** and generate a link. An email is not sent automatically; the link must be delivered privately.
2. Open the link on the same local server in a separate tab, set a password, and sign in at /store/dashboard.
3. Confirm only approved vendor catalog products are shown, add products to the cart, update quantities and submit a test order request.
4. Return to Admin > Stores; check Incoming order requests.
5. Sign in as the representative assigned to that store at /representative/dashboard; use Place an order request for a store, select the store, and submit a test request.
6. Return to the store dashboard to confirm its request history includes both requests. Reps cannot submit for unassigned stores, and store users cannot submit for other stores.

## Production blockers

- Order requests are **not** actual orders, commission earnings, vendor dispatches or payment instructions. A separate reviewed order lifecycle and product-line snapshots with commission terms must be designed before issuing real commercial orders.
- State and product-specific retail and distribution licensing, expiration and compliance enforcement are not automated. Do not permit actual restricted-product orders through this prototype without applicable licensing verification.
- Stock availability, per-store eligibility and pricing, tax, shipping, seller-specific restrictions, age checks where required, account recovery, customer notification, invitation revocation, and fulfillment are not implemented.
- Test in local development with non-sensitive fictional stores and catalog products. No production deployment is authorized.
