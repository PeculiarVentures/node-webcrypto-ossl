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
                 "src/core/key_exp.cpp",
                 "src/core/scoped_ssl.h",
				 "src/core/scoped_ssl.cpp",
                 "src/core/logger.cpp",
                 "src/core/excep.cpp",
                 # "src/source/key.cpp",
                 "src/rsa/common.h",
                 "src/rsa/rsa_gen.cpp",
                 "src/rsa/rsa_jwk.cpp",
                 "src/rsa/rsa_pkcs1.cpp",
                 "src/rsa/rsa_oaep.cpp",
                 "src/node/common.h",
                 "src/node/common.cpp",
                 "src/node/w_key.cpp",
                 "src/node/async_rsa.cpp"
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
                                        "openssl_root%": "C:/Build-OpenSSL-VC-64"
                                    }
                                },
                                {
                                    "variables": {
                                        "openssl_root%": "C:/Build-OpenSSL-VC-32"
                                    }
                                }
                            ]
                        ],
                        "libraries": [
                            "-l<(openssl_root)/lib/libeay32.lib"
                        ],
                        "include_dirs": [
                            "<(openssl_root)/include"
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