{
    "variables": {
        "node_shared_openssl%": "true"
    },
    "targets": [
        {
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "target_name": "nodessl",
            "sources": [
                 "src/main.cpp",
                 "src/core/common.h",
                 "src/core/define.h",
                 "src/core/bn.cpp",
                 "src/core/key_exp.cpp",
                 "src/core/scoped_ssl.h",
				 "src/core/scoped_ssl.cpp",
                 "src/core/logger.cpp",
                 "src/core/excep.cpp",
                 "src/core/digest.cpp",
                 "src/rsa/common.h",
                 "src/rsa/rsa_gen.cpp",
                 "src/rsa/rsa_jwk.cpp",
                 "src/rsa/rsa_pkcs1.cpp",
                 "src/rsa/rsa_oaep.cpp",
                 "src/rsa/rsa_pss.cpp",
                 "src/ec/common.h",
                 "src/ec/ec_gen.cpp",
                 "src/ec/ec_dsa.cpp",
                 "src/ec/ec_dh.cpp",
                 "src/ec/ec_jwk.cpp",
                 "src/aes/common.h",
                 "src/aes/aes_def.h",
                 "src/aes/aes_gen.cpp",
                 "src/aes/aes_cbc.cpp",
                 "src/aes/aes_gcm.cpp",
                 "src/node/common.h",
                 "src/node/common.cpp",
                 "src/node/w_key.cpp",
                 "src/node/w_aes.cpp",
                 "src/node/w_core.cpp",
                 "src/node/async_rsa.cpp",
                 "src/node/async_ec.cpp",
                 "src/node/async_aes.cpp",
                 "src/node/async_core.cpp"
            ],
            "cflags_cc": ["-fexceptions"],
            "conditions": [
                [
                    "OS=='win'",
                    {
                        "conditions": [
                            [
                                "target_arch=='x64'",
                                {
                                    "variables": {
                                        "openssl_root%": "C:/github/openssl"
                                    }
                                },
                                {
                                    "variables": {
                                        "openssl_root%": "C:/github/openssl"
                                    }
                                }
                            ]
                        ],
                        "libraries": [
                            "-l<(openssl_root)/out32dll/libeay32.lib"
                        ],
                        "include_dirs": [
                            "<(openssl_root)/inc32"
                        ]
                    },
                    {
                        "conditions": [
                            [
                                "node_shared_openssl=='false'",
                                {
                                    "include_dirs": [
                                        "<(node_root_dir)/deps/openssl/openssl/include"
                                    ]
                                }
                            ]
                        ]
                    }
                ],
                [ 'OS=="mac"', {
                  'xcode_settings': {
                    'OTHER_CPLUSPLUSFLAGS' : ['-std=c++11','-stdlib=libc++', '-v'],
                    'OTHER_LDFLAGS': ['-stdlib=libc++'],
                    'MACOSX_DEPLOYMENT_TARGET': '10.7',
                    'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                  },
                }]
            ]
        }
    ]
}
