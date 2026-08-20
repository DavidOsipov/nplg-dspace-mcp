import eslint from "@eslint/js";
import typescript from "typescript";
import typescriptEslint from "typescript-eslint";

const contractFiles = [
  "contracts/zod/baseline-contracts.mjs",
  "contracts/zod/asvs-evidence-contracts.mjs",
  "contracts/zod/capability-contracts.mjs",
  "tests/contracts/zod_baseline_contracts.test.mjs",
  "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  "tests/contracts/zod_contracts.test.mjs",
];
const forbiddenJSDocAnyKinds = new Set([
  typescript.SyntaxKind.AnyKeyword,
  typescript.SyntaxKind.JSDocAllType,
  typescript.SyntaxKind.JSDocUnknownType,
]);

const taskOnePolicyPlugin = {
  meta: {
    name: "nplg-task1-contract-policy",
    version: "1.0.0",
  },
  rules: {
    "no-jsdoc-any": {
      create(context) {
        return {
          Program(program) {
            const sourceFile = context.sourceCode.parserServices
              .esTreeNodeToTSNodeMap?.get(program);
            if (sourceFile === undefined) {
              throw new Error(
                "task1/no-jsdoc-any requires TypeScript parser services",
              );
            }
            const visitedJSDocNodes = new Set();

            const inspectJSDocNode = (node) => {
              if (visitedJSDocNodes.has(node)) {
                return;
              }
              visitedJSDocNodes.add(node);
              if (forbiddenJSDocAnyKinds.has(node.kind)) {
                const startOffset = node.getStart(sourceFile);
                context.report({
                  loc: {
                    start: context.sourceCode.getLocFromIndex(startOffset),
                    end: context.sourceCode.getLocFromIndex(node.end),
                  },
                  messageId: "forbidden",
                });
              }
              typescript.forEachChild(node, inspectJSDocNode);
            };

            const inspectTypeScriptNode = (node) => {
              for (const jsDocNode of typescript.getJSDocCommentsAndTags(node)) {
                inspectJSDocNode(jsDocNode);
              }
              typescript.forEachChild(node, inspectTypeScriptNode);
            };

            inspectTypeScriptNode(sourceFile);
          },
        };
      },
      meta: {
        docs: {
          description: "Disallow explicit and equivalent any types in JSDoc",
        },
        messages: {
          forbidden:
            "JSDoc type expressions must not use `any`, `*`, or `?`; use `unknown` and narrow it.",
        },
        schema: [],
        type: "problem",
      },
    },
  },
};

const withContractFiles = (configuration) => ({
  ...configuration,
  files: contractFiles,
});

export default typescriptEslint.config(
  withContractFiles(eslint.configs.recommended),
  ...typescriptEslint.configs.strictTypeChecked.map(withContractFiles),
  ...typescriptEslint.configs.stylisticTypeChecked.map(withContractFiles),
  {
    files: contractFiles,
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.contracts.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    linterOptions: {
      noInlineConfig: true,
      reportUnusedDisableDirectives: "error",
    },
    plugins: {
      task1: taskOnePolicyPlugin,
    },
    rules: {
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-check": true,
          "ts-expect-error": true,
          "ts-ignore": true,
          "ts-nocheck": true,
        },
      ],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/no-unsafe-type-assertion": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "task1/no-jsdoc-any": "error",
    },
  },
);
