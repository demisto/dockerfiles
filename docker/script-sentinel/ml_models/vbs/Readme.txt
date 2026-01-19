Model supports VBS/VBE files (* will be replaced in the upcoming months with a new model.txt (same feature vector))
TH - 0.9
model.txt (Standard LightGBM output) -  gs://hornet_vbs/models/70_30_trial_143/model.txt

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
        ./hornet_genvector vbs fec8b619468f8e1f93b905d0acffa69e07a2f7730079920748b6949b6ebd7035 out
    Example output:
        out/fec/fec8b619468f8e1f93b905d0acffa69e07a2f7730079920748b6949b6ebd7035.bin - file that contains the binary vector (sparse double feature vector)
