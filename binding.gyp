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
                "src/key.cpp"
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
                ]
            ]
        }
    ]
}