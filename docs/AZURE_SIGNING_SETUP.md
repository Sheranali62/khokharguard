# Authenticode Signing KhokharGuard Releases (Azure Artifact Signing)

This guide walks through enabling Authenticode signing for KhokharGuard
release binaries so Windows SmartScreen no longer warns on freshly
downloaded installers.

The CI workflow (`.github/workflows/ci.yml`) is already wired for this:
when the repository secrets listed in [step 5](#step-5-add-the-github-secrets)
exist, the frozen executables are signed immediately after the
PyInstaller build and the installer is signed after the Inno Setup
compile. When the secrets are absent, both steps skip themselves and
artefacts are published unsigned.

Two authentication paths are supported — prefer **OIDC workload
identity federation** (no stored secret that can leak or expire
unnoticed); the client-secret triple is the fallback:

The signing uses **Azure Artifact Signing** (the service formerly known
as *Trusted Signing*), which issues short-lived certificates and
performs the signing in Microsoft's cloud — the private key never
exists where you (or CI) can lose it.

---

## What you need before starting

| Requirement | Notes |
|---|---|
| Azure subscription | Signing is a paid service (a low-cost monthly tier plus a per-signature meter); check the [current pricing](https://azure.microsoft.com/pricing/details/artifact-signing/). |
| Organization legal identity | Certificate profiles require identity validation (see step 2). Individual developers validate as an **individual**; companies as an **organization**. |
| GitHub repository admin | To add the repository secrets. |
| ~2–3 business days of patience | Identity validation and first certificate issuance are asynchronous. |

> **No Visual Studio requirement.** Signing happens server-side; CI only
> needs the GitHub Action, which the workflow already pins
> (`azure/artifact-signing-action@v2`).

---

## Step 1 — Create an Artifact Signing account

1. Sign in to the [Azure portal](https://portal.azure.com) with an
   account that can create resources in your subscription.
2. **Create a resource** → search for **Artifact Signing**
   (if your tenant still shows the old name, it appears as
   **Trusted Signing** — it is the same service).
3. Fill in:
   - **Subscription / Resource group**: any; a dedicated
     `rg-khokharguard-signing` group keeps role assignments tidy.
   - **Account name**: e.g. `khokharguard-signing`. This becomes the
     `AZURE_SIGNING_ACCOUNT` secret.
   - **Pricing tier**: Basic is sufficient for Authenticode
     (Public Trust) signing.
4. Review + create. Note the **region** — the account's regional
   endpoint URL is shown on the account's overview page and looks like:

   ```
   https://eus.codesigning.azure.net/
   ```

   That URL (region-specific, including the trailing part shown for
   your account) is the `AZURE_SIGNING_ENDPOINT` secret.

## Step 2 — Identity validation (one-time)

Certificate issuance is blocked until the billing account's identity is
validated. In the Artifact Signing account → **Identity validation**
(earlier versions: *Identity Validation* blade under *Settings*):

1. Start a validation for the **legal entity** that owns the
   subscription (individual or organization).
2. Validation is performed with DigiCert. Individuals provide
   government ID + a phone verification; organizations provide
   registration documents (e.g. articles of incorporation) and
   a verified phone number.
3. Wait for the status to become **Completed** (usually minutes to two
   business days). You cannot create a certificate profile before this
   succeeds — this is the step most people forget.

## Step 3 — Create a certificate profile

In the Artifact Signing account → **Certificate profiles** → **Create**:

1. **Certificate type**: **Public Trust** (this is what SmartScreen
   recognises).
2. **Identity**: your validated identity from step 2.
3. **Common name (CN)**: the publisher name that will appear in the
   UAC/Properties dialogs — e.g. your legal name or organization name.
   Choose carefully: it is baked into every signed release.
4. Create, then note the **profile name** (e.g. `khokharguard-release`).
   That string is the `AZURE_SIGNING_CERT_PROFILE` secret.

The certificate itself is short-lived (about 3 days) and rotates
automatically; because every signature is **RFC 3161 timestamped**
(the workflow pins `http://timestamp.acs.microsoft.com`), signatures
remain valid after the certificate expires.

## Step 4 — Grant the CI principal permission to sign

The workflow authenticates as an **app registration** (service
principal). The signing action uses `DefaultAzureCredential`; the
`azure/login` step in the workflow establishes the credential before
the sign steps run.

1. **Create the app registration** (skip if you already have one for CI):
   - Microsoft Entra ID → **App registrations** → **New registration**
     → name `github-khokharguard-ci`, single tenant.
   - Copy the **Application (client) ID** and the tenant's
     **Directory (tenant) ID** from the overview page.
2. **Grant the signer role**, scoped as narrowly as possible:
   - Artifact Signing account → **Access control (IAM)** →
     **Add role assignment**.
   - Role: **Artifact Signing Certificate Profile Signer**
     (on older tenants: *Trusted Signing Certificate Profile Signer*).
   - Members: the `github-khokharguard-ci` app registration.
   - Do **not** grant Contributor at subscription level — the signer
     role at the account scope is the least privilege that works.
3. **Choose the credential the CI principal will use**:

   **Option A (recommended) — OIDC workload identity federation:**
   - App registration → **Certificates & secrets** →
     **Federated credentials** → **Add credential**.
   - Scenario: *GitHub Actions deploying Azure resources*.
   - Organization: `Sheranali62` (your GitHub org or username).
   - Repository: `localguard`.
   - Entity type: **Tag**; value: `v*` (signing only ever runs on
     `vX.Y.Z` tag builds — the narrowest sensible trust).
   - Also copy the **Subscription ID** hosting the signing account
     (Subscriptions → overview) — `azure/login` needs it for the
     token exchange.

   **Option B (fallback) — client secret:**
   - **Certificates & secrets** → **New client secret** → copy the
     secret **value** immediately (it is shown once).
   - Store it as `AZURE_CLIENT_SECRET` and rotate it on a schedule.

## Step 5 — Add the GitHub secrets

Repository → **Settings** → **Secrets and variables** → **Actions** →
**New repository secret**. Add all four base secrets, then the
credential secret for the option chosen in step 4:

| Secret name | Value | Where to find it |
|---|---|---|
| `AZURE_TENANT_ID` | Directory (tenant) ID | Entra ID app overview |
| `AZURE_CLIENT_ID` | Application (client) ID | Entra ID app overview |
| `AZURE_SUBSCRIPTION_ID` | Subscription hosting the signing account | Subscriptions → overview *(OIDC option)* |
| `AZURE_SIGNING_ENDPOINT` | Regional endpoint URL | Signing account overview, e.g. `https://eus.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | Account name | e.g. `khokharguard-signing` |
| `AZURE_SIGNING_CERT_PROFILE` | Certificate profile name | e.g. `khokharguard-release` |
| `AZURE_CLIENT_SECRET` | Secret value from step 4 option B | Shown once at creation *(client-secret option only)* |

Nothing else needs to change in the workflow:

- **OIDC option:** the workflow runs `azure/login@v3` with the three
  IDs (it requires the job-level `id-token: write` permission, which is
  already set), and both sign steps then execute because
  `AZURE_SUBSCRIPTION_ID` is non-empty.
- **Client-secret option:** the sign steps read the environment triple
  directly; `azure/login` skips itself.
- **Migrating from client secret to OIDC later:** add the federated
  credential and `AZURE_SUBSCRIPTION_ID`, delete the
  `AZURE_CLIENT_SECRET` secret, re-run — no workflow edit needed.

## Step 6 — Verify a signed release

1. Push a version tag (`git tag -a vX.Y.Z && git push origin vX.Y.Z`)
   and watch the Actions run. Both **Sign frozen binaries** and
   **Sign installer** steps should now execute (previously skipped).
2. Download the `KhokharGuard-Setup-vX.Y.Z` artefact and verify
   locally in PowerShell:

   ```powershell
   $sig = Get-AuthenticodeSignature .\KhokharGuard_Setup_vX.Y.Z.exe
   $sig.Status        # Valid
   $sig.SignerCertificate.Subject   # CN = your step-3 publisher name
   ```

   `Valid` (not `UnknownError`/`NotTrusted`) means the chain and
   RFC 3161 timestamp check out.

3. Remember that a *valid* signature still needs **reputation** before
   SmartScreen stops prompting entirely — that builds automatically as
   downloads accumulate. A valid signature plus timestamp removes the
   "Unknown publisher" class of warning immediately.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Signing step fails `403` with `SignerRoleRequirementNotMet` | The service principal lacks the **Certificate Profile Signer** role at the signing-account scope (step 4.2). |
| `CertificateProfileNotFound` | `AZURE_SIGNING_CERT_PROFILE` must be the profile **name**, not its display string or resource ID. |
| `IdentityValidationRequired` when creating the profile | Step 2 not completed — nothing to do but wait for DigiCert. |
| Endpoint errors / `name does not exist` | `AZURE_SIGNING_ENDPOINT` must be the region-specific account endpoint from the overview page, not the bare service domain. |
| Signature shows `Status: UnknownError` | Almost always a missing/unreachable timestamp; the workflow already sets the Microsoft RFC 3161 server — check corporate TLS interception if verifying from inside a corporate network. |
| Secrets added but steps still skip | The steps gate on `AZURE_CLIENT_ID` being non-empty at the **job** level, plus either `AZURE_CLIENT_SECRET` (fallback) or `AZURE_SUBSCRIPTION_ID` (OIDC); confirm you added repository *secrets*, not environment *variables*. |
| OIDC: `azure/login` fails with `AADSTS70021` / no tenant-level federated credential | The federated credential doesn't match the run's claim. For tag builds the subject must resolve to `repo:Sheranali62/localguard:ref:refs/tags/vX.Y.Z` — re-check org, repo, entity type **Tag** and value `v*` in step 4 option A. |

## Security notes

- **Prefer the OIDC path.** Workload identity federation means there is
  no client secret stored in GitHub at all; trust is bound to this
  repository's tag builds via the federated credential, and tokens live
  for minutes only.
- If you use the client-secret fallback, treat the secret as a signing
  capability: rotate it on a schedule (Entra ID → App registrations →
  Certificates & secrets) and update `AZURE_CLIENT_SECRET`.
- Scope: the signer role assignment is limited to the Artifact Signing
  account resource; the principal cannot read repo secrets, deploy
  resources, or sign with any other profile.
- The signing service's private-key model means there is no key file
  to leak, no HSM to manage, and no offline key ceremony to run.
