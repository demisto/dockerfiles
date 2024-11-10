#!/bin/bash

export OMP_NUM_THREADS=$(nproc)
exec "$@"