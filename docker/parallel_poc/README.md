# Parallel Build POC (CIAC-17423)

Minimal, self-contained proof-of-concept that builds **each changed docker image in
its own CI job** (per-image parallelism), instead of building the whole batch in a
single job. This is the core mechanism for CIAC-17423: because the runner disk /
artifact limit is applied **per job**, one image per job keeps every job well under
the 5 GB limit.

> This POC is intentionally independent of the `infra` pipeline. It proves the
> parallel fan-out works before we wire it into the real pipeline.
>
> Located under `docker/` (rather than `utils/`) because the repo's `.gitignore`
> ignores `/Utils`, which also matches a lowercase `utils/` sub-dir on
> case-insensitive filesystems. `docker/` is tracked, so these files are committed.

## Files

| File | Purpose |
|---|---|
| [`get_changed_images.py`](get_changed_images.py) | Discovers changed image dirs under `docker/` via `git diff` and prints them (json / matrix / lines). |
| [`generate_child_pipeline.py`](generate_child_pipeline.py) | Turns the image list into a GitLab **child pipeline** with one `build_docker.sh <image>` job per image. |
| [`../../.gitlab/poc-parallel.gitlab-ci.yml`](../../.gitlab/poc-parallel.gitlab-ci.yml) | The POC pipeline: `generate-matrix` → trigger child pipeline (fan-out). |

## Why a dynamic child pipeline?

GitLab needs the set of jobs known at pipeline-definition time, but the changed-image
set is only known at runtime. The standard GitLab pattern for a runtime-computed job
set is a **dynamic child pipeline**: a job generates a YAML artifact, and a `trigger`
job runs it.

```
poc:generate-matrix   ->   poc:run-builds (trigger)
  (discover + emit YAML)      -> poc-build:<imageA>
                              -> poc-build:<imageB>   (parallel, one per image)
                              -> poc-build:<imageC>
```

## Run locally (dry check)

```bash
# 1. Discover changed images (vs. master):
python docker/parallel_poc/get_changed_images.py --diff-compare "origin/master...HEAD" --format lines --output changed_images.txt
cat changed_images.txt

# 2. Generate the child pipeline YAML:
python docker/parallel_poc/generate_child_pipeline.py --images-file changed_images.txt --output poc-child-pipeline.yml
cat poc-child-pipeline.yml
```

Each generated job runs the existing single-image build primitive:

```bash
bash docker/build_docker.sh --save-dir "artifacts/<image>" "<image>"
```

## Run on CI

This POC is wired into the MR pipeline via a `local` include in
[`../../.gitlab/.gitlab-ci.yml`](../../.gitlab/.gitlab-ci.yml). On every commit to the
branch you should see:

1. `poc:generate-matrix` — logs the changed images and the generated child YAML.
2. `poc:run-builds` — a triggered child pipeline with one `poc-build:<image>` job per
   changed image, each building a single image. If they all go green, per-image
   parallel building works.

Adjust `POC_BASE_REF` (default `origin/master`) to your MR target branch if needed.

## Notes / limitations (POC scope)

- Uses `docker:24.0` + `docker:24.0-dind` so `docker build` works inside CI. The
  real pipeline may use a different runner/executor.
- Each job builds the **real** image from `docker/<image>/`. There is no synthetic
  fallback: if a real build fails (e.g. a base image can't be pulled), the job
  fails. This is intentional so the run reflects the true 30-way parallel build
  capability of the runners.
- No push, no scan, no carry-over/GCS, no Slack — those come in the full
  implementation (see the plan). The POC only proves the **parallel per-image build**
  succeeds.
- An empty change set produces a harmless `poc-build:noop` job so the child pipeline
  is always valid.
- **Remove the `local` include from `.gitlab/.gitlab-ci.yml` once the POC is
  validated** so it doesn't run on every pipeline.
