FROM alpine:latest

# Minimal, dependency-free image used only to exercise the cosign sign job in CI
# and its verification via utils/verify_signature.sh. It intentionally installs
# nothing so it builds fast and its sole purpose is to be pushed and signed.
LABEL org.opencontainers.image.description="Cosign signing smoke-test image (not for production use)."
