#!/usr/bin/env python3
import pyjq

golden_data = {"param_name": "PKG_TAG_NAME", "param_type": None}

data = dict(
    parameters=[
        dict(name="PKG_TAG_NAME", value="trunk"),
        dict(name="GIT_COMMIT", value="master"),
        dict(name="TRIGGERED_JOB", value="trunk-buildall"),
    ],
    id="2013-12-27_00-09-37",
    changeSet=dict(items=[], kind="git"),
)

d = pyjq.first('.parameters[] | {"param_name": .name, "param_type":.type}', data)

assert d == golden_data
