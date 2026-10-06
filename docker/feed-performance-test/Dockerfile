# Last modified: 2026-10-06T04:48:12.588104+00:00
FROM demisto/faker3:1.0.0.13531018 AS build
RUN mkdir -p /perf
COPY script.py /perf

WORKDIR /perf
RUN python -u script.py

FROM demisto/python3:3.12.14.13495286
RUN mkdir -p /perf
WORKDIR /perf
COPY --from=build /perf/ips.csv .
COPY --from=build /perf/domains.csv .
COPY --from=build /perf/hashes.csv .
