# verify_signature.sh

Verify the Sigstore/cosign signature of a Cortex XSOAR/XSIAM Docker image.

Signatures are **not** stored next to the image. They live in a sibling repo in
the same org/registry, with the image name prefixed by `sig-`
(`demisto/python3` -> `demisto/sig-python3`). [`verify_signature.sh`](verify_signature.sh)
derives that repo for you, so you only pass the image reference.

The signing side (the `cosign` sign job and its `cosign_sign_pushed.sh` script)
lives in the **infra** repo (the `${CI_PROJECT_NAMESPACE}/infra` dockerfiles
template) and is documented there. This repo only provides the verifier.

## The cosign key

The public key needed to verify signatures (`cosign.pub`) is published here:

- https://xsoar.pan.dev/docs/integrations/cosign-signature

The private signing key never leaves GCP KMS; only the public key is
distributed to verifiers. Download `cosign.pub` from the link above and keep it
in your working directory (or point `PUBLIC_KEY` at it).

## Requirements

- `cosign` on PATH (https://github.com/sigstore/cosign). cosign v2 and v3 both work.
- The cosign public key saved as `cosign.pub` in the current directory
  (override with `PUBLIC_KEY=/path/to/cosign.pub`).

## Usage

```bash
./utils/verify_signature.sh <org>/<image>:<tag>
./utils/verify_signature.sh <org>/<image>@sha256:<digest>
```

Example:

```bash
./utils/verify_signature.sh demisto/python3:3.10
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PUBLIC_KEY` | Optional. Path to the cosign public key. Default `cosign.pub` in the current directory. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Signature verified. |
| `1` | Usage or environment error (missing arg, cosign not installed, public key not found). |
| `>1` | Verification failed (cosign returned an error). |

## Notes

- The script passes `--insecure-ignore-tlog=true` because signing runs with the
  Rekor transparency log **off** (`COSIGN_TLOG_UPLOAD=false` on the signing
  side), so there is no tlog entry to check.
- To verify manually without the helper, point cosign at the sibling `sig-`
  repo yourself:

  ```bash
  COSIGN_REPOSITORY=demisto/sig-python3 \
    cosign verify --key cosign.pub --insecure-ignore-tlog=true demisto/python3:<version>
  ```
