# Traffic Architect Mac signing

Generic signing automation. **Keep this repository private until an end-to-end test and log review pass.**

Game kits, signed downloads, and detailed build logs belong only in
[the private builds repository](https://github.com/pranshu6/traffic-architect-mac-builds).
Never commit certificates, API keys, passwords, game code, or game archives here.

## One-time setup

In this repository's **Settings → Secrets and variables → Actions**, add:

| Secret | Value |
| --- | --- |
| `PRIVATE_BUILDS_TOKEN` | A fine-grained GitHub personal access token owned by `pranshu6`, restricted to **only** `traffic-architect-mac-builds`, with **Contents: read and write**. Set an expiry and renew it when needed. |
| `APPLE_CERTIFICATE_BASE64` | Base64 of the friend's Developer ID Application `.p12` (including its private key). |
| `APPLE_CERTIFICATE_PASSWORD` | The friend's password for that `.p12`; this is not the Mac login password. |
| `APPLE_API_KEY_BASE64` | Base64 of the friend's notarization `.p8` key. |
| `APPLE_API_KEY_ID` | The API key ID. |
| `APPLE_API_ISSUER` | The API issuer ID. |

The Apple credentials are used only for signing/notarization, imported into a temporary keychain,
and removed when the runner is disposed. A physical Mac is not needed for this workflow.
Do not add anyone as a repository writer unless trusted with these credentials.

## Each update

1. In the **private builds repo**, create a release tagged `kit-VERSION-COMMIT`, e.g. `kit-1.1.3-715bd9c4`.
   Attach the matching demo and full `*-mac-kit.zip` files. The version and commit must match their `dist/build.json`.
2. Here, open **Actions → Sign Mac builds → Run workflow**, and enter that kit tag.
3. Wait for success. The workflow summary links to a **private signed-build release** containing two `.tar.gz` files and their SHA-256 verification record.
4. Send those two archives to the developer, or let him download them with private repo access.
   Do not unpack on Windows; preserve the archives for extraction on macOS/Linux/WSL.

It checks the packaged version, commit, demo/full flags, Electron runtime fuses,
Intel and Apple Silicon architectures, then extracts the final archives and checks
signature, Gatekeeper acceptance, and notarization tickets. No Steam upload is performed.

## Failures

No automatic rebuild or resubmission is made. Detailed logs, with known credential values
redacted, are saved as a diagnostics release in the private repo. Do not publish those logs.
A failure before tools start may have no diagnostics archive. Check secret setup first.
If Apple reports an agreement issue, only the Apple account holder can resolve it.
Check Apple's existing submission before retrying a run that timed out during notarization.

## Public/private split and limits

Only the generic workflow and short fixed status messages belong here. There are no public
Actions artifacts or caches of game files. Signed archives and diagnostic logs are uploaded
straight to private GitHub Releases, outside Actions artifact storage. Everyone downloading
those private releases needs access to the private repo.

Running the Mac job here after this repo becomes public uses GitHub's standard public runner
allowance. While private, it uses the owner's private Actions compute allowance. Making this
repo public is a separate owner decision after review; this setup does not change visibility.

The separation limits accidental exposure, but is not isolation from trusted kit code:
kit scripts and dependencies execute on the signing runner and must be trusted. Do not add
pull-request signing, arbitrary remote scripts, public artifact uploads, or verbose secret
printing. Secret masking alone is insufficient. Actions are pinned to reviewed commit hashes;
update those pins deliberately. The cross-repo token has access to only the builds repo.

Official references:
- https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
