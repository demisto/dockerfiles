Model supports PS1 files

TH - 0.85
model.txt (Standard LightGBM output) - gs://hornet_production_materials/PS/PS_model_2022_12/model_files/01/model.txt
model.bin (PANW proprietarty format) - gs://hornet_production_materials/PS/PS_model_2022_12/model_files/01/model.bin

Tools -
Makefile: https://gitlab.xdr.pan.local/xdr/agent/development/traps/agent/-/blob/master/win/src/lib/hornetps/Makefile?ref_type=heads

genpsvector -> Creates the feature vector (then can feed this to generic code that runs with model.txt)
    Example CmdLine:
        ./genpsvector /home/vkozhukhov_paloaltonetworks_com/hornet_ps/data/PS_PowerShellCorpus/malicious/test/C2Code.ps1 ./fe_vectors/
    Example output:
        TODO
psscanner -> End to end score generation (needs model.bin)
    Example CmdLine:
        psscanner ../prod_model.bin /home/vkozhukhov_paloaltonetworks_com/hornet_ps/data/PS_PowerShellCorpus/malicious/test/C2Code.ps1
    Example output:
        /home/vkozhukhov_paloaltonetworks_com/hornet_ps/data/PS_PowerShellCorpus/malicious/test/C2Code.ps1,0.974566
