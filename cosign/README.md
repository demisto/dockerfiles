# Sigstore/cosign signing (CIAC-16370)

Adds a **Sigstore / cosign** signature to every Docker image built and pushed by
the dockerfiles flow, replacing the legacy **Docker Content Trust (DCT / Notary v1)**
signing. Signing is done in a dedicated CI job that is independent of the
build/push step and of the legacy DCT sign job, so the DCT path can be removed
later without touching the build.

## Deliverables

| File | Purpose |
| --- | --- |
| [`cosign_sign_pushed.sh`](cosign_sign_pushed.sh) | Signs images that were already built/pushed. Reads the built-images list, adds a cosign signature per image, stores it in a sibling signature repo. |
| [`../utils/verify_signature.sh`](../utils/verify_signature.sh) | Verifier helper: derives the signature repo and runs `cosign verify` for a given image. |
| `cosign.pub` | Public key for verifiers (not secret). Derived from the KMS key with `cosign public-key` (see below) and distributed to consumers. |

The GitLab CI `cosign` sign job that runs [`cosign_sign_pushed.sh`](cosign_sign_pushed.sh)
against `artifacts/built_dockers.txt` lives in the **infra dockerfiles template**
(the `${CI_PROJECT_NAMESPACE}/infra` project, alongside the build/push and legacy
DCT sign jobs), not in this repo. This repo only provides the signing script it
invokes.

## Where signatures are stored

The signature is **not** co-located with the image. It goes to a sibling repo in
the **same org/registry**, with the image name prefixed by `sig-`:

    <org>/<image>  ->  <org>/sig-<image>

For example `demisto/python3` -> `demisto/sig-python3`. cosign is pointed at that
repo via `COSIGN_REPOSITORY`, which keeps the `sha256-<digest>.sig` artifacts out
of the image repo's tag list. You do **not** set `COSIGN_REPOSITORY` yourself; the
script derives it (`COSIGN_SIG_PREFIX`, default `sig-`). The CI user therefore
needs **push** rights on the `<org>/sig-*` repos.

Signing does **not** modify the image itself.

## Signing key (KMS only)

A cosign **KMS key reference** is the ONLY supported signing key; static PEM keys
are not supported. The private key never leaves KMS; CI holds only the
`gcpkms://` reference, and authentication comes from the runner's GCP
credentials (no password/raw key in CI). The reference is supplied to the job as
`COSIGN_KEY_REF` from the infra dockerfiles template (a resource path, not a
secret).

Derive the public key for verifiers:

```bash
cosign public-key --key "$COSIGN_KEY_REF" > cosign.pub
```

## CI variables

| Variable | Purpose |
| --- | --- |
| `COSIGN_KEY_REF` | Required. KMS key reference (`gcpkms://...`); the only supported key type. Supplied by the infra dockerfiles template. |
| `DOCKERHUB_USER` | Docker Hub user with **push** rights to the `<org>/sig-*` signature repos. |
| `DOCKERHUB_PASSWORD` | Docker Hub password / access token. |
| `COSIGN_SIG_PREFIX` | Optional. Prefix for the sibling signature repo. Default `sig-`. |
| `COSIGN_TLOG_UPLOAD` | Optional. `true` to upload to the public Rekor log. Default `false`. |
| `COSIGN_VERSION` | Optional. cosign release to install if absent. Default `v2.4.1`. |
| `DRY_RUN` | Optional. `true` to report what would be signed without signing. |

## Run locally

```bash
export DOCKERHUB_USER=... DOCKERHUB_PASSWORD=...
export COSIGN_KEY_REF='gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>'

# Sign the images listed in artifacts/built_dockers.txt:
cosign/cosign_sign_pushed.sh

# Or sign specific refs without the artifact file:
BUILT_DOCKERS='demisto/python3:3.10,demisto/crypto:1.0' cosign/cosign_sign_pushed.sh

# Dry-run (no signing):
DRY_RUN=true cosign/cosign_sign_pushed.sh
```

## Verify a signature

Use [`../utils/verify_signature.sh`](../utils/verify_signature.sh) (it derives the
sibling `sig-` repo for you; keep `cosign.pub` in the working directory or set
`PUBLIC_KEY=/path/to/cosign.pub`):

```bash
./utils/verify_signature.sh demisto/python3:<version>
```

Or manually, pointing cosign at the sibling signature repo:

```bash
COSIGN_REPOSITORY=demisto/sig-python3 \
  cosign verify --key cosign.pub --insecure-ignore-tlog=true demisto/python3:<version>
```

`--insecure-ignore-tlog=true` is required because signing runs with Rekor off
(`COSIGN_TLOG_UPLOAD=false`).

## Rollback

Unset `COSIGN_KEY_REF` (or disable the cosign sign job). The signing step becomes
a no-op with no other code changes.

## Notes

- Rekor is kept **off** (`COSIGN_TLOG_UPLOAD=false`; verify with
  `--insecure-ignore-tlog=true`) to avoid publishing private image digests to the
  public transparency log.
- Keyless signing (GitLab OIDC + Fulcio + public Rekor) was considered but NOT
  chosen for the same reason.
- Once cosign verification is enforced by consumers, the legacy DCT path can be
  removed with no changes to build or to cosign.
