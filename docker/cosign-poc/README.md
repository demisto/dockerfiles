# Dual-Sign POC — DCT + Sigstore/cosign (CIAC-16370)

## Dual-signing an EXISTING demisto image from CI (recommended proof)

To prove we can dual-sign a **real, already-published** `demisto` image (which
already carries a DCT/Notary signature) without running the full build, use the
manually-triggered CI job [`.gitlab/ci/cosign-poc-dual-sign.yml`](../../.gitlab/ci/cosign-poc-dual-sign.yml)
which runs [`dual_sign_ci_test.sh`](dual_sign_ci_test.sh). It pulls the image,
adds a cosign signature by digest, and verifies both signatures.

**1. Add CI/CD variables** (Settings → CI/CD → Variables, masked + protected):

- `COSIGN_PRIVATE_KEY` — PEM contents of the cosign private key
- `COSIGN_PASSWORD` — password protecting the private key
- `COSIGN_PUBLIC_KEY` — PEM contents of the cosign public key (for verify)
- `DOCKERHUB_USER` — Docker Hub user with **push** rights to the target repo
- `DOCKERHUB_PASSWORD` — Docker Hub password / access token

cosign stores the signature as an extra `sha256-<digest>.sig` artifact **in the
same repo** as the image, so the user needs write access to that repo
(e.g. `demisto/accessdata`). Signing does **not** modify the image itself.

**2. Wire the job into the pipeline** (one line in the repo-root pipeline config):

    include:
      - local: "/.gitlab/ci/cosign-poc-dual-sign.yml"

The job is inert unless `RUN_COSIGN_POC == "true"`, so it never affects normal runs.

**3. Trigger it** — CI/CD → Pipelines → Run pipeline, with variables:

- `RUN_COSIGN_POC` = `true`
- `TARGET_IMAGE` = `demisto/python3:3.7.5.4328` (default)
- `COSIGN_TLOG_UPLOAD` = `false` (default — no public Rekor upload)
- `VERIFY_DCT` = `true` (default — also verify the existing DCT signature)

Then press ▶ on the `cosign-poc:dual-sign` manual job. A green job = **dual-sign
confirmed** (DCT present & verified, cosign added & verified).

Safety: point `TARGET_IMAGE` at a `devdemisto/...` copy first for a run against a
non-production namespace. `COSIGN_TLOG_UPLOAD=false` keeps signatures out of the
public transparency log (recommended for internal images).

---

This POC proves that a Docker image built by [`docker/build_docker.sh`](../build_docker.sh)
can carry **two** signatures simultaneously:

1. The existing **Docker Content Trust (DCT / Notary v1)** signature — unchanged.
2. A new **Sigstore / cosign** signature — added additively.

The goal is a safe transition window in which consumers can verify with *either*
mechanism before DCT is eventually removed.

## What changed in the build script

All changes live in [`docker/build_docker.sh`](../build_docker.sh) and are **additive,
non-fatal, and disabled by default**:

- A new `cosign_sign` helper signs a **pushed image by its registry digest**.
- It is invoked after a successful push to:
  - the container registry (`CR_REPO`, e.g. `us.gcr.io/xsoar-registry`), and
  - Docker Hub (in addition to the existing DCT signature).
- If `COSIGN_PRIVATE_KEY` is unset **or** the `cosign` binary is missing, signing
  is skipped and the build behaves exactly as before. A cosign failure only logs a
  warning; it never fails the build.

## Required environment variables (CI secrets)

| Variable | Purpose |
| --- | --- |
| `COSIGN_PRIVATE_KEY` | PEM contents of `cosign.key` (the private key). |
| `COSIGN_PASSWORD` | Password protecting the private key. |

## 1. Generate a key pair (one-time)

```bash
# Produces cosign.key (private, password-protected) and cosign.pub (public).
COSIGN_PASSWORD='choose-a-strong-password' cosign generate-key-pair
```

Store the values as CI secrets:

```bash
# COSIGN_PRIVATE_KEY = full PEM contents of cosign.key
# COSIGN_PASSWORD    = the password you chose above
```

In GitLab: **Settings → CI/CD → Variables** — add both as *masked, protected*
variables. For `COSIGN_PRIVATE_KEY` use "type: Variable" and paste the whole PEM
(cosign reads it via `env://COSIGN_PRIVATE_KEY`).

Keep `cosign.pub` in the repo / distribute it to verifiers — it is not secret.

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
# optional secondary registry (GCR) — where images are pulled from:
export CR_REPO=us.gcr.io/xsoar-registry CR_USER=... CR_PASSWORD=...
export COSIGN_PRIVATE_KEY="$(cat cosign.key)"
export COSIGN_PASSWORD='...'

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

Or manually:

```bash
# cosign (new):
cosign verify --key cosign.pub devdemisto/python3:<version>

# DCT (existing):
DOCKER_CONTENT_TRUST=1 docker pull devdemisto/python3:<version>
```

Both succeeding = **dual-sign confirmed**.

## Rollback

Unset `COSIGN_PRIVATE_KEY` (or remove the CI secret). The script immediately
reverts to DCT-only behavior — no code changes needed.

## Production follow-up (out of POC scope)

- Move from a static key to **keyless signing** (GitLab OIDC + Fulcio + Rekor
  transparency log) via `cosign sign --yes <digest>` with an OIDC token.
- Decide whether to sign the secondary/`latest` tags.
- Once cosign verification is enforced by consumers, remove the DCT path
  (`sign_setup` / `commit_dockerfiles_trust` / the `dockerfiles-trust` git repo).
