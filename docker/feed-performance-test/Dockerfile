# Last modified: 2026-07-21T09:21:00.910273+00:00
FROM demisto/faker3:1.0.0.11195141 AS build
RUN mkdir -p /perf
COPY script.py /perf

WORKDIR /perf
RUN python -u script.py

FROM demisto/python3:3.12.13.10116658
RUN mkdir -p /perf
WORKDIR /perf
COPY --from=build /perf/ips.csv .
COPY --from=build /perf/domains.csv .
COPY --from=build /perf/hashes.csv .
