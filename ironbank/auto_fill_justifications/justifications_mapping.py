###################### Anchore Compliance Results ######################
ANCHORE_COMPLIANCE_RESULTS = {'cbff271f45d32e78dcc1979dbca9c14d': 'The docker images we create are being used by our server: Cortex XSOAR. More info at: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/docker/docker-images-in-demisto.html. Referring to the product design, the dockers are run by the Cortex XSOAR server and the server has some constraints on the expected format of the docker images. The server assumes that the default user of an image is "root". The product does have a configuration to run as non-root the docker images. See: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/docker/docker-hardening-guide/run-docker-with-non-root-internal-users.html. But for the rare cases that an image needs to run with a "root" internal user, the product assumes the default configured user is "root" and will not pass this as a parameter to the "docker run" command. For this reason, we want to maintain this compatibility and set the default user to "root".'}


###################### Twistlock Vulnerability Results ######################
TWISTLOCK_VUNERABILITY_RESULTS = {'CVE-2020-14422': 'PIP 9.0.3 is not in use, the PIP was upgraded manually to version 20.3.4.',
                                  'CVE-2021-3733': 'The XOSAR software is using this module to communicate with internal 3rd party applications only that are running on the same network and it is not in use for communication with public services. We do not see any risk or potential attack from the services that XSOAR is communicating with.',
                                  'CVE-2021-3737': 'The XOSAR software is using this module to communicate with internal 3rd party applications only that are running on the same network and it is not in use for communication with public services. We do not see any risk or potential attack from the services that XSOAR is communicating with.',
                                  'CVE-2019-9674': 'The XSOAR software is not using python3-libs, the only use for python 3 is by yum/rpm. The XSOAR software is not using any of the above tools, the only use for them is at the Docker build stage.',
                                  'CVE-2020-27619': 'The XSOAR software is not using python3-libs, the only use for python 3 is by yum/rpm. The XSOAR software is not using any of the above tools, the only use for them is at the Docker build stage.',
                                  'CVE-2020-8492': 'The XOSAR software is using this module to communicate with internal 3rd party applications only that are running on the same network and it is not in use for communication with public services. We do not see any risk or potential attack from the services that XSOAR is communicating with.',
                                  'CVE-2021-42694': 'The XOSAR software basiclly using the docker image to runs python code, the output of the python script are manipulated and displayed on the client browser side.',
                                  'CVE-2020-17049': 'The XSOAR software does not use this module, this module was installed as dependency for systemd.',
                                  'CVE-2021-4019': 'The XSOAR software doesnt use the vim module in the runtime executions, the only use for vim is only for debugging purpose which done manually by our engeneers on the docker itself.'
                                  }

###################### Anchore CVE Results ######################
ANCHORE_CVE_RESULTS = {'GHSA-5xp3-jfq3-5q8x': 'The pip in the XSOAR docker images in the Ironbank environment is not allowed to communicate with any Git and the only use for pip is to installed packages that are downloaded in advance and pre approved by the Ironbank team.',
                       'CVE-2021-43618': 'The XSOAR software does not use this module, this module was installed as dependency for systemd.'
                       }


SHEET_JUSTIFICATIONS_MAPPERS = {'Anchore Compliance Results': {'column_name': 'trigger_id',
                                                               'justifications': ANCHORE_COMPLIANCE_RESULTS},
                                'Twistlock Vulnerability Results': {'column_name': 'id',
                                                                    'justifications': TWISTLOCK_VUNERABILITY_RESULTS},
                                'Anchore CVE Results': {'column_name': 'cve',
                                                        'justifications': ANCHORE_CVE_RESULTS}}