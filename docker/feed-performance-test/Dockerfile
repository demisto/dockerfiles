FROM demisto/faker3:1.0.0.58112 AS build
RUN mkdir -p /perf
COPY script.py /perf

WORKDIR /perf
RUN python -u script.py

FROM demisto/python3:3.10.10.47713
RUN mkdir -p /perf
WORKDIR /perf
COPY --from=build /perf/ips.csv .
COPY --from=build /perf/domains.csv .
COPY --from=build /perf/hashes.csv .
