{
    "variables": {
        'runtime%': 'node', 
        'openssl_dir%': '<(node_root_dir)/deps/openssl/openssl',
        'openssl_1_0_2%': 0
    },
    "targets": [
        {
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                "<(openssl_dir)/include"
            ],
            "target_name": "nodessl",
            "sources": [
                "src/main.cpp",
                "src/core/common.h",
                "src/core/define.h",
                "src/core/key_exp.cpp",
                "src/core/scoped_ssl.h",
                "src/core/scoped_ssl.cpp",
                "src/core/logger.cpp",
                "src/core/excep.cpp",
                "src/core/digest.cpp",
                "src/core/bn.cpp",
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
                "src/aes/aes_ecb.cpp",
                "src/aes/aes_cbc.cpp",
                "src/aes/aes_gcm.cpp",
                "src/aes/aes_ctr.cpp",
                "src/hmac/common.h",
                "src/hmac/hmac_gen.cpp",
                "src/hmac/hmac_sign.cpp",
                "src/pbkdf2/common.h",
                "src/pbkdf2/pbkdf2_derive.cpp",
                "src/node/common.h",
                "src/node/common.cpp",
                "src/node/w_key.cpp",
                "src/node/w_aes.cpp",
                "src/node/w_hmac.cpp",
                "src/node/w_pbkdf2.cpp",
                "src/node/w_core.cpp",
                "src/node/async_rsa.cpp",
                "src/node/async_ec.cpp",
                "src/node/async_aes.cpp",
                "src/node/async_hmac.cpp",
                "src/node/async_pbkdf2.cpp",
                "src/node/async_core.cpp"
            ],
            "cflags_cc": ["-fexceptions"],
            "conditions": [
                [
                    'runtime != "node"', {
                        'defines': [
                            'OPENSSL_1_0_2=<(openssl_1_0_2)'
                        ],
                        'conditions': [
                            [
                                'OS == "win"', {
                                    'libraries': [
                                        '-l<(openssl_dir)/lib/libeay32.lib'
                                    ]
                                },
                                # OS != "win"
                                {
                                    'libraries': [
                                        '<(openssl_dir)/lib/libcrypto.a' # static lib
                                    ]
                                },
                            ],
                        ]
                    }
                ],
                [
                    'OS=="mac"',
                    {
                        'xcode_settings': {
                            'OTHER_CPLUSPLUSFLAGS': ['-std=c++14', '-stdlib=libc++', '-v'],
                            'OTHER_LDFLAGS': ['-stdlib=libc++'],
                            'MACOSX_DEPLOYMENT_TARGET': '10.7',
                            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                        },
                    },
                    'OS=="win"',
                    {
                        'msvs_settings': {
                            'VCCLCompilerTool': {
                                'ExceptionHandling': 1,
                            }
                        }
                    }
                ]
            ]
        }
    ]
}
