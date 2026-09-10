# Registering the Entra ID (Azure AD) application

What to send a client's IT team when a project protected by
`supplement-bacon/laravel-azure-sso` needs an application created — or re-created — in
their Microsoft tenant.

Typical situations:

- new project going live,
- the client migrates or merges tenants (the app registration does **not** follow the
  domain, so SSO breaks the day the migration lands),
- the client rebuilds the app registration from scratch.

---

## 1. How the integration works

```
Browser (SPA back-office)  ──login──▶  Microsoft Entra ID (client tenant)
        │                                      │
        │ ◀────────── ID token ────────────────┘
        │
        └── Authorization: Bearer <token> ──▶  Laravel API
                                                 │
                                                 ├─ aud === AZURE_SSO_CLIENT_ID
                                                 ├─ iss === issuer of AZURE_SSO_TENANT_ID
                                                 ├─ signature checked against the tenant JWKS
                                                 │  (public key cached on the `local` disk)
                                                 └─ injects the `oid` claim into the request
```

Things to know before writing to a client:

- The API needs **exactly two values**: the application (client) ID and the directory
  (tenant) ID. **No client secret**, no certificate — the middleware only verifies a
  signature against Microsoft's public keys. Ask for a secret only if the project makes
  server-side Microsoft Graph calls somewhere else in its code.
- The tenant ID is part of the validation (`iss` must match that tenant's issuer), so a
  token issued by another tenant is rejected even with the right client ID. A tenant
  change is therefore always a breaking change.
- **The package authenticates, it does not authorise.** It answers "is this a valid token
  from that tenant for that app", nothing more. Read §3 before you send anything.

---

## 2. Procedure to send to the client

> Copy-paste block; adjust the app name and the redirect URI.

**Create the app registration**

Microsoft Entra admin center (`entra.microsoft.com`) → Identity → Applications →
App registrations → **New registration**

- Name: `<APP NAME>`
- Supported account types: **Accounts in this organizational directory only (single
  tenant)**
- Redirect URI: platform **Single-page application (SPA)**, value
  `https://<BACK-OFFICE HOST>/login-redirect`
- **Register**

**Authentication**

On the **Authentication** blade, under *Implicit grant and hybrid flows*, tick
**ID tokens**, then **Save**.

**Restrict access — required, not optional**

**Enterprise applications → `<APP NAME>` → Properties** → set **Assignment required?**
to **Yes**, then **Save**.

Then **Users and groups** → add only the people who should administer the back-office.

**Values to send back**

- Application (client) ID
- Directory (tenant) ID

---

## 3. Why "Assignment required" is the whole access control

The Laravel side auto-provisions: on a valid token whose `oid` is unknown, the app
creates the account and logs it in (`LoginSSOAdmin` in the Abbaye project; same pattern
elsewhere). There is no allow-list, no role, no invitation step in the code.

So the only thing standing between the client's directory and a back-office account is
the Entra app assignment. With **Assignment required? = No** (the default), *every user
of the tenant* who reaches the front-end URL gets an admin account created for them on
first sign-in. In a small tenant that is sloppy; in a group-wide tenant it is an
incident.

Always ask for it explicitly, and re-check it after any tenant migration — the setting
does not carry over with a new registration.

If the project needs finer control, that is a code change (allow-list on the email/`oid`
claim, or roles), not a portal setting.

---

## 4. Notes for us, not for the client

**Implicit grant checkboxes.** Ticking *ID tokens* is only required for front-ends still
on the implicit / hybrid flow (MSAL.js v1). A front-end on MSAL v2+ uses authorization
code + PKCE and needs neither checkbox — leave them off on new projects and only enable
*ID tokens* if sign-in fails with `AADSTS700054`. Never ask for *Access tokens* unless
you know the front-end sends `accessToken` rather than `idToken`.

**Several environments.** Staging and production are separate hosts, so each needs its
own redirect URI. Either add both to a single registration (fine when both serve the same
users), or ask for two registrations and keep two sets of credentials. Redirect URIs must
match exactly — scheme, host and path.

**Custom domains.** A back-office domain change means adding the new redirect URI in the
client's tenant *before* the switch, or sign-in breaks at cutover.

---

## 5. Configuration on our side

```dotenv
AZURE_SSO_CLIENT_ID=00000000-0000-0000-0000-000000000000
AZURE_SSO_TENANT_ID=00000000-0000-0000-0000-000000000000
```

Then:

```bash
php artisan config:clear
```

The middleware caches the tenant's signing key at `storage/app/azure-cache/public-key`.
It is re-fetched when the token's `kid` stops matching, but after a tenant change delete
it to avoid one failed request:

```bash
rm -f storage/app/azure-cache/public-key
```

Check the tenant answers before blaming the app:

```bash
curl -s https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration | jq .issuer
```

---

## 6. Tenant migration: what happens to existing accounts

`oid` is **per tenant**. A user re-created in a new tenant arrives with a new `oid`, so
the row stored against the old one is orphaned.

- **Auto-provisioning projects** (the Abbaye pattern — the accounts table holds nothing
  but `azure_id`): nothing to do. Each user gets a fresh row at first sign-in. Old rows
  are dead weight; clean them up once everyone has reconnected.
- **Projects that hang data off the account** (roles, ownership, audit trail, preferences):
  the mapping has to be rebuilt, or users lose their history. Two ways:
  1. ask the client for `email + new Object ID` for each user and update `azure_id`;
  2. re-link by the token's email claim at first sign-in and overwrite `azure_id` — only
     acceptable on a single-tenant app with verified addresses, and only as a one-shot
     migration window, never as permanent behaviour.

Decide this **before** the client creates the app, and say so in the same email.

---

## 7. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `401` on every API call, token looks valid | `AZURE_SSO_CLIENT_ID` does not match the token's `aud` — front-end and API point at different registrations |
| `Invalid token issuer` | `AZURE_SSO_TENANT_ID` still points at the old tenant |
| `No key found. Invalid kid provided.` | Stale cached key, or the tenant JWKS is unreachable from the server — delete the cache, check egress to `login.microsoftonline.com` |
| `AADSTS50011` at sign-in | Redirect URI missing or mistyped in the registration |
| `AADSTS700054` at sign-in | *ID tokens* not enabled while the front-end uses the implicit flow |
| Anyone in the client's tenant can log in | *Assignment required?* left on **No** — see §3 |
| Sign-in works, user lost their history | `oid` changed and the mapping was not rebuilt — see §6 |

---

## 8. Checklist

- [ ] App registration created in the **right** tenant, single-tenant
- [ ] Redirect URI(s) exact, one per environment
- [ ] *ID tokens* enabled if the front-end uses the implicit flow
- [ ] **Assignment required? = Yes**, users/groups assigned
- [ ] Client ID and tenant ID received and set in `.env`
- [ ] `config:clear` run, public-key cache dropped
- [ ] `oid` migration handled (or confirmed unnecessary)
- [ ] Sign-in tested with a real client account, staging then production
