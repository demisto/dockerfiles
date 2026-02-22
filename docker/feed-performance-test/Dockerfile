FROM demisto/faker3:1.0.0.6977863 AS build
RUN mkdir -p /perf
COPY script.py /perf

WORKDIR /perf
RUN python -u script.py

FROM demisto/python3:3.12.12.7090913
RUN mkdir -p /perf
WORKDIR /perf
COPY --from=build /perf/ips.csv .
COPY --from=build /perf/domains.csv .
# Last modified: 2026-02-11T15:18:34.933506+00:00
COPY --from=build /perf/hashes.csv .
