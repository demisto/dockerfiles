# Dual-Sign POC: DCT + Sigstore/cosign (CIAC-16370)

## Dual-signing an EXISTING demisto image from CI (recommended proof)

To prove we can dual-sign a **real, already-published** `demisto` image (which
already carries a DCT/Notary signature) without running the full build, use the
manually-triggered CI job [`.gitlab/ci/cosign-poc-dual-sign.yml`](../../.gitlab/ci/cosign-poc-dual-sign.yml)
which runs [`dual_sign_ci_test.sh`](dual_sign_ci_test.sh). It pulls the image,
adds a cosign signature by digest, and verifies both signatures.

**1. Add CI/CD variables** (Settings > CI/CD > Variables, masked + protected):

Signing key (KMS only; the URI from [`keys.txt`](keys.txt)):

- `COSIGN_KEY_REF` : KMS key reference, e.g.
  `gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>`
  (no raw key or password in CI)
- `COSIGN_PUBLIC_KEY` : PEM contents of the cosign public key (for verify),
  derived from the KMS key with `cosign public-key --key "$COSIGN_KEY_REF"`
- `DOCKERHUB_USER` : Docker Hub user with **push** rights to the signature repo
- `DOCKERHUB_PASSWORD` : Docker Hub password / access token

Storage (the DECIDED design: a separate, per-image signature repo). By default
cosign stores the `sha256-<digest>.sig` artifact **in the same repo** as the
image; this POC redirects it with `COSIGN_REPOSITORY`, which the build computes
**automatically per image** from the image's org:

    <org>/<image>  ->  <org>-signatures/<image>

For example `demisto/python3` -> `demisto-signatures/python3` and
`devdemisto/python3` -> `devdemisto-signatures/python3`. You do **not** set
`COSIGN_REPOSITORY` yourself; the script derives it (see `cosign_signature_repo`
in [`build_docker.sh`](../build_docker.sh)). The CI user therefore needs **push**
rights on the `<org>-signatures` repos (not on the image repo), which keeps the
`<org>/*` image tag lists clean. Container-registry (GCR) signing is off by
default and only enabled with `COSIGN_SIGN_CR=true`, in which case the signature
goes to `${CR_REPO}/<org>-signatures/<image>`.

Signing does **not** modify the image itself.

**2. Wire the job into the pipeline** (one line in the repo-root pipeline config):

    include:
      - local: "/.gitlab/ci/cosign-poc-dual-sign.yml"

The job is inert unless `RUN_COSIGN_POC == "true"`, so it never affects normal runs.

**3. Trigger it** : CI/CD > Pipelines > Run pipeline, with variables:

- `RUN_COSIGN_POC` = `true`
- `TARGET_IMAGE` = `demisto/python3:3.7.5.4328` (default)
- `COSIGN_TLOG_UPLOAD` = `false` (default: no public Rekor upload)
- `VERIFY_DCT` = `true` (default: also verify the existing DCT signature)

Then press the play button on the `cosign-poc:dual-sign` manual job. A green job =
**dual-sign confirmed** (DCT present & verified, cosign added & verified).

Safety: point `TARGET_IMAGE` at a `devdemisto/...` copy first for a run against a
non-production namespace. `COSIGN_TLOG_UPLOAD=false` keeps signatures out of the
public Rekor transparency log (keyed/offline verify; avoids leaking private image
digests).

---

This POC proves that a Docker image built by [`docker/build_docker.sh`](../build_docker.sh)
can carry **two** signatures simultaneously:

1. The existing **Docker Content Trust (DCT / Notary v1)** signature (unchanged).
2. A new **Sigstore / cosign** signature (added additively).

The goal is a safe transition window in which consumers can verify with *either*
mechanism before DCT is eventually removed.

## What changed in the build script

All changes live in [`docker/build_docker.sh`](../build_docker.sh) and are **additive,
non-fatal, and disabled by default**:

- A new `cosign_sign` helper signs a **pushed image by its registry digest**,
  using `COSIGN_KEY_REF` (the KMS key from `keys.txt`; the only supported key type).
  It derives the signature repo per image (`<org>-signatures/<image>`) and points
  cosign at it via `COSIGN_REPOSITORY`.
- It is invoked after a successful push to:
  - Docker Hub (in addition to the existing DCT signature), where the signature is
    written to the separate `<org>-signatures/<image>` repo.
  - the container registry (`CR_REPO`, e.g. `us.gcr.io/xsoar-registry`) **only when
    `COSIGN_SIGN_CR=true`**, where the signature goes to
    `${CR_REPO}/<org>-signatures/<image>`. Off by default.
- If `COSIGN_KEY_REF` is unset **or** the `cosign` binary is missing, signing is
  skipped and the build behaves exactly as before. A cosign failure only logs a
  warning; it never fails the build.

## Required environment variables (CI secrets)

| Variable | Purpose |
| --- | --- |
| `COSIGN_KEY_REF` | Required. KMS key reference (`gcpkms://...` from `keys.txt`); the only supported key type. No raw key/password in CI. |
| `COSIGN_SIGN_CR` | Optional. `true` to also sign the GCR/CR copy (default: Docker Hub only). |

The signature repo is derived automatically (`<org>-signatures/<image>`); you do
not set `COSIGN_REPOSITORY` in normal use.

## 1. Set up the signing key (KMS only)

The KMS key from [`keys.txt`](keys.txt) is the ONLY supported signing key. The
private key never leaves KMS; CI holds only the `gcpkms://` reference. Grant the
CI identity the `signerVerifier` role on the key, then set the reference and
derive the public key:

```bash
export COSIGN_KEY_REF='gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>'

# Public key for verifiers (not secret) - store as COSIGN_PUBLIC_KEY / cosign.pub:
cosign public-key --key "$COSIGN_KEY_REF" > cosign.pub
```

In GitLab: **Settings > CI/CD > Variables**, add `COSIGN_KEY_REF` (masked,
protected). No password is needed with KMS. Static PEM keys are not supported.

Keep `cosign.pub` in the repo / distribute it to verifiers; it is not secret.

## 2. Make cosign available in CI

Add to the build job (GitLab CI `before_script` or the CI base image):

```bash
COSIGN_VERSION=v2.4.1
curl -sSfL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
  -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign
cosign version
```

## 3. Run the POC (locally, targeting the dev org / registry)

Never target the production `demisto` org during the POC. Use a dev target and a
single image (the positional arg builds only that image):

```bash
export DOCKER_ORG=devdemisto
export DOCKERHUB_USER=... DOCKERHUB_PASSWORD=...
# optional secondary registry (GCR), where images are pulled from:
export CR_REPO=us.gcr.io/xsoar-registry CR_USER=... CR_PASSWORD=...

# KMS key (the only supported key type; no raw key/password in CI):
export COSIGN_KEY_REF='gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n>'

# The signature repo is derived automatically (devdemisto -> devdemisto-signatures);
# no need to set COSIGN_REPOSITORY. To also sign the GCR copy, set COSIGN_SIGN_CR=true.

# Build + push + dual-sign a single image (e.g. python3):
docker/build_docker.sh python3
```

Dry-run first to confirm wiring without pushing/signing:

```bash
docker/build_docker.sh --upload --last-upload-commit HEAD~1 --files-to-prs /dev/null --dry-run python3
# Look for: "[DRY-RUN] Would have cosign-signed: ..."
```

## 4. Verify both signatures (the proof)

Use [`verify_dual_sign.sh`](verify_dual_sign.sh):

```bash
./docker/cosign-poc/verify_dual_sign.sh devdemisto/python3:<version> cosign.pub
```

Or manually. The signature lives in the separate `<org>-signatures/<image>` repo,
so point cosign at it with `COSIGN_REPOSITORY`:

```bash
# cosign (new), Docker Hub image (signature in devdemisto-signatures/python3):
COSIGN_REPOSITORY=devdemisto-signatures/python3 \
  cosign verify --key cosign.pub --insecure-ignore-tlog=true devdemisto/python3:<version>

# cosign (new), GCR image signed with COSIGN_SIGN_CR=true:
COSIGN_REPOSITORY=us.gcr.io/xsoar-registry/devdemisto-signatures/python3 \
  cosign verify --key cosign.pub --insecure-ignore-tlog=true \
  us.gcr.io/xsoar-registry/devdemisto/python3:<version>

# DCT (existing):
DOCKER_CONTENT_TRUST=1 docker pull devdemisto/python3:<version>
```

(The [`verify_dual_sign.sh`](verify_dual_sign.sh) helper derives the signature
repo for you, so the manual `COSIGN_REPOSITORY` is only needed for ad-hoc checks.)

`--insecure-ignore-tlog=true` is required because we sign with Rekor off
(`COSIGN_TLOG_UPLOAD=false`).

Both succeeding = **dual-sign confirmed**.

## Rollback

Unset the signing key (`COSIGN_KEY_REF`), or remove the CI secret. The script
immediately reverts to DCT-only
behavior; no code changes needed.

## Production plan (DECIDED, see the DR deck)

- Sign with a **KMS key from the start** (`COSIGN_KEY_REF=gcpkms://...`); no raw
  key/password in CI. Derive and publish `cosign.pub` for verifiers.
- Store signatures in a **separate, per-image repo** derived from the image org:
  `<org>/<image>` -> `<org>-signatures/<image>` (e.g. `demisto/python3` ->
  `demisto-signatures/python3`, `devdemisto/python3` -> `devdemisto-signatures/python3`).
  The build sets `COSIGN_REPOSITORY` automatically. GCR/CR signing is opt-in via
  `COSIGN_SIGN_CR=true` (signature -> `${CR_REPO}/<org>-signatures/<image>`).
- Keep **Rekor off** (`COSIGN_TLOG_UPLOAD=false`; verify with
  `--insecure-ignore-tlog=true`).
- **Dual-sign** (DCT + cosign) during the grace period until the Dec 8, 2026 DCT
  retirement deadline.
- **Backfill** the ~380 in-use `:latest` images by digest so opt-in verification
  is consistent from day one.
- Publish the cosign public key + `cosign verify` instructions (replacing
  `docker trust inspect`).
- Once cosign verification is enforced by consumers, remove the DCT path
  (`sign_setup` / `commit_dockerfiles_trust` / the `dockerfiles-trust` git repo).

Note: keyless signing (GitLab OIDC + Fulcio + public Rekor log) was considered but
NOT chosen; it publishes signing metadata to a public log, which is undesirable for
private images.
