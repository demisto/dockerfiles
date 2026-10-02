import os
import subprocess


def run(*cmd: str) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return (result.stdout + result.stderr).strip()


# google-cloud-cli (renamed from google-cloud-sdk) and the GKE auth plugin
run("gcloud", "--version")
run("gsutil", "--version")
run("gke-gcloud-auth-plugin", "--version")

# neo4j pinned to NEO4J_VERSION, with the matching APOC plugin
neo4j_version = os.environ["NEO4J_VERSION"]
installed_neo4j_version = run("neo4j-admin", "--version")
assert (
    installed_neo4j_version == neo4j_version
), f"expected neo4j {neo4j_version}, got {installed_neo4j_version}"
apoc_jar = f"/var/lib/neo4j/plugins/apoc-{neo4j_version}-core.jar"
assert os.path.isfile(apoc_jar), f"missing APOC plugin: {apoc_jar}"

# cosign pinned to COSIGN_VERSION
cosign_version = os.environ["COSIGN_VERSION"].lstrip("v")
cosign_output = run("cosign", "version")
assert (
    cosign_version in cosign_output
), f"expected cosign {cosign_version}, got: {cosign_output}"

print("All is good. gitlab-content-ci tools verified successfully")
