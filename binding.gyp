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
                 "src/source/common.h",
                 "src/source/common.cpp",
                 "src/source/ossl_wrap.h",
				 "src/source/ossl_wrap.cpp",
                 "src/source/logger.cpp",
                 "src/source/excep.cpp",
                 # "src/source/key.cpp",
                 "src/source/key_rsa.cpp",
                 "src/source/w_key.cpp"
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