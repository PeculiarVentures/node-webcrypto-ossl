import path from "path";
import alias from "@rollup/plugin-alias";
import typescript from "@rollup/plugin-typescript";
// @ts-ignore
import pkg from "./package.json";

const banner = [
  "/**",
  " * Copyright (c) 2020, Peculiar Ventures, All rights reserved.",
  " */",
  "",
].join("\n");
const input = "lib/index.ts";
const external = [
  "crypto",
  "os",
  "path",
  "fs",
  ...Object.keys(pkg.dependencies)
];


export default [
  // main
  {
    input,
    plugins: [
      typescript({
        module: "ES2015",
        removeComments: true,
      }),
      alias({
        entries: [
          { find: "native", replacement: "../../../build/Release/nodessl.node" },
        ]
      }),
    ],
    external: (name) => external.includes(name) || path.basename(name) === "nodessl.node",
    output: [
      {
        banner,
        file: pkg.main,
        format: "cjs",
      },
      {
        banner,
        file: pkg.module,
        format: "es",
      },
    ],
  },
];
