#!/usr/bin/env bash
# Load App Store Connect creds from 1Password and run a fastlane lane (default: beta →
# archive + upload to TestFlight). Keeps all secrets out of the repo + the shell history.
#
# ┌─ BLOCKER B-APPLE (what must exist in op://$OP_VAULT/appstore/ before `beta` works) ─┐
# │  key_id      ✅ <ASC_KEY_ID>   issuer_id ✅   team_id ✅ <APPLE_TEAM_ID>   bundle_id ✅ ai.caladon.app │
# │  issuer_id   ✅ present                                                                 │
# │  api_key_p8  ✅ the ASC API key .p8 contents (validated: authenticates to ASC)         │
# │  team_id     ❌ currently "#": the 10-char Apple Developer Team ID                       │
# │  bundle_id   ❌ currently "#": the registered bundle id (e.g. ai.caladon.app)    │
# │  Also: an active Apple Developer Program membership + agreements accepted.              │
# └────────────────────────────────────────────────────────────────────────────────────────┘
# Usage:  ./testflight.sh build   # compile-check only (no creds needed)
#         ./testflight.sh beta    # archive + upload to TestFlight (needs the above)
set -euo pipefail
cd "$(dirname "$0")"
LANE="${1:-beta}"

if [ "$LANE" = "build" ]; then
  command -v fastlane >/dev/null || { echo "fastlane not installed (gem install fastlane)"; exit 2; }
  exec fastlane build
fi

req() { op read "op://$OP_VAULT/appstore/$1" 2>/dev/null; }
ASC_KEY_ID="$(req key_id)"; ASC_ISSUER_ID="$(req issuer_id)"
ASC_KEY_P8="$(req api_key_p8)"; [ -z "$ASC_KEY_P8" ] && ASC_KEY_P8="$(req credential)"; SWIFTY_TEAM_ID="$(req team_id)"; SWIFTY_BUNDLE_ID="$(req bundle_id)"
missing=""
[ -n "$ASC_KEY_ID" ]    || missing="$missing key_id"
[ -n "$ASC_ISSUER_ID" ] || missing="$missing issuer_id"
[ -n "$ASC_KEY_P8" ]    || missing="$missing credential(.p8)"
{ [ -n "$SWIFTY_TEAM_ID" ] && [ "$SWIFTY_TEAM_ID" != "#" ]; }   || missing="$missing team_id"
{ [ -n "$SWIFTY_BUNDLE_ID" ] && [ "$SWIFTY_BUNDLE_ID" != "#" ]; } || missing="$missing bundle_id"
[ -z "$missing" ] || { echo "❌ B-APPLE incomplete — missing/placeholder:$missing"; echo "   See the header of this script."; exit 2; }
command -v fastlane >/dev/null || { echo "fastlane not installed (gem install fastlane)"; exit 2; }

export ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_P8 SWIFTY_TEAM_ID SWIFTY_BUNDLE_ID
fastlane "$LANE"
