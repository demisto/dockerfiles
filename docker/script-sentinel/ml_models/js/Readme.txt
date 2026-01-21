Model supports JS/JSE files
TH - 0.5
model.txt (Standard LightGBM output) - gs://hornet_production_materials/JScript/rc_1004_trial_2/model.txt js_from_bucket_model.txt

Tools -

Makefile: https://gitlab.xdr.pan.local/xdr/agent/development/traps/agent/-/blob/master/win/src/lib/hornetvbs/ai/Makefile?ref_type=heads
Compiled binary (ubuntu 20): https://gitlab.xdr.pan.local/xdr/research-ml/hornet-js/-/blob/master/agent_feature_extractor/hornet_genvector?ref_type=heads

hornet_genvector -> Creates the feature vector (then can feed this to generic code that runs with model.txt). This binary supports both VBS and JS
    As building not via the buildsystem i have the 2 dependancies offline (supplied in genvector_deps folder)
    1. unzip compact_enc_det.zip to hornetvbs dir
    2. change the Makefile (line 21+22) to
        LIB_CED = ../compact_enc_det/b245d1481049ccf68a48be5517d59925a0aab8c9/lib/libced.a
        INC_CED = ../compact_enc_det/b245d1481049ccf68a48be5517d59925a0aab8c9/include

    Example CmdLine:
        ./hornet_genvector js fec8b619468f8e1f93b905d0acffa69e07a2f7730079920748b6949b6ebd7035 out
    Example output:
        out/fec/fec8b619468f8e1f93b905d0acffa69e07a2f7730079920748b6949b6ebd7035.bin - file that contains the binary vector (sparse double feature vector)