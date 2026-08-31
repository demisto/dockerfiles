# Last modified: 2026-08-26T16:53:14.110156+00:00
FROM demisto/faker3:1.0.0.11376519 AS build
RUN mkdir -p /perf
COPY script.py /perf

WORKDIR /perf
RUN python -u script.py

FROM demisto/python3:3.12.14.12343672
RUN mkdir -p /perf
WORKDIR /perf
COPY --from=build /perf/ips.csv .
COPY --from=build /perf/domains.csv .
COPY --from=build /perf/hashes.csv .
