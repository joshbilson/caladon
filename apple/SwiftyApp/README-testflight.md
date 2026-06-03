# Shipping Caladon to TestFlight (DoD #1)

The app builds for the iOS simulator + macOS today (unsigned, no Apple account needed — see
CI's `app-build` job). Getting it onto **TestFlight** needs the Apple credentials below
(**B-APPLE**). Auth is via an **App Store Connect API key** (`.p8`) — no Apple-ID password,
CI-friendly. Everything is read from 1Password at run time; no secret is in the repo.

## Pipeline
- `./testflight.sh build` — compile-check for the iOS simulator (no creds; runs `fastlane build`).
- `./testflight.sh beta` — `xcodegen generate` → `build_app` (app-store export, auto-signing
  via the API key) → `upload_to_testflight`. Reads creds from `op://$OP_VAULT/appstore/*`.
- `fastlane/Fastfile` + `fastlane/Appfile` hold the lanes; `testflight.sh` injects the creds.

## B-APPLE — what's in 1Password (`op://$OP_VAULT/appstore/`)
| field | status | what it is |
|---|---|---|
| `key_id` | ✅ present | ASC API key id (App Store Connect → Users and Access → Integrations → Keys) |
| `issuer_id` | ✅ present | the issuer id shown on that Keys page |
| `credential` | ❌ **missing** | the **entire `.p8` file contents** (`-----BEGIN PRIVATE KEY----- … -----END …`). Downloadable **once** when the key is created — paste it into this CONCEALED field |
| `team_id` | ❌ **placeholder `#`** | the 10-char Apple Developer **Team ID** (membership → Membership details) |
| `bundle_id` | ❌ **placeholder `#`** | the registered **bundle id** (`ai.caladon.app`); register it under Identifiers, or auto-create on first `beta` |

Also required: an **active Apple Developer Program** membership with agreements accepted.

## Once those three are filled
```
cd apple/SwiftyApp && ./testflight.sh beta
```
First run creates the distribution cert + provisioning profile via the API key
(`-allowProvisioningUpdates`), archives the app, and uploads the build to TestFlight.

> The `beta` lane is config-complete but **cannot be validated until B-APPLE is finished**
> (signing/upload require the real key + IDs). The `build` lane is validated (it wraps the
> same `xcodebuild` the CI app-build job runs).
