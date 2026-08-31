import eslint from "@eslint/js";
import typescript from "typescript";
import typescriptEslint from "typescript-eslint";

const contractFiles = [
  "contracts/zod/baseline-contracts.mjs",
  "contracts/zod/asvs-evidence-contracts.mjs",
  "contracts/zod/capability-contracts.mjs",
  "contracts/zod/recovery-contracts.mjs",
  "contracts/zod/models.ts",
  "contracts/zod/contract.test.ts",
  "tests/contracts/zod_baseline_contracts.test.mjs",
  "tests/contracts/zod_asvs_evidence_contracts.test.mjs",
  "tests/contracts/zod_contracts.test.mjs",
  "tests/contracts/zod_recovery_contracts.test.mjs",
];
const zodLengthGovernedSources = new Set([
  "/contracts/zod/asvs-evidence-contracts.mjs",
  "/contracts/zod/contract.test.ts",
  "/contracts/zod/models.ts",
]);
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
    "no-native-zod-string-length": {
      create(context) {
        return {
          Program(program) {
            const parserServices = context.sourceCode.parserServices;
            const sourceFile = parserServices.esTreeNodeToTSNodeMap?.get(program);
            const typeChecker = parserServices.program?.getTypeChecker();
            if (sourceFile === undefined || typeChecker === undefined) {
              throw new Error(
                "task1/no-native-zod-string-length requires TypeScript parser services",
              );
            }
            if (
              ![...zodLengthGovernedSources].some((suffix) =>
                sourceFile.fileName.endsWith(suffix)
              )
            ) {
              return;
            }
            const forbiddenMethods = new Set(["length", "max", "min"]);
            const forbiddenCheckTypes = new Set([
              "$ZodCheckLengthEquals",
              "$ZodCheckMaxLength",
              "$ZodCheckMinLength",
            ]);
            const isZodString = (node) =>
              typeChecker.getTypeAtLocation(node).getSymbol()?.getName() === "ZodString";
            const reportNativeLength = (node) => {
              context.report({
                loc: {
                  start: context.sourceCode.getLocFromIndex(
                    node.getStart(sourceFile),
                  ),
                  end: context.sourceCode.getLocFromIndex(node.end),
                },
                messageId: "native",
              });
            };
            const inspectTypeScriptNode = (node) => {
              if (
                typescript.isPropertyAccessExpression(node)
                && forbiddenMethods.has(node.name.text)
                && isZodString(node.expression)
              ) {
                reportNativeLength(node.name);
              } else if (
                typescript.isCallExpression(node)
                && typescript.isPropertyAccessExpression(node.expression)
                && node.expression.name.text === "check"
                && isZodString(node.expression.expression)
              ) {
                for (const argument of node.arguments) {
                  const checkType = typeChecker.getTypeAtLocation(argument);
                  if (forbiddenCheckTypes.has(checkType.getSymbol()?.getName() ?? "")) {
                    reportNativeLength(argument);
                  }
                }
              }
              typescript.forEachChild(node, inspectTypeScriptNode);
            };

            inspectTypeScriptNode(sourceFile);
          },
        };
      },
      meta: {
        docs: {
          description:
            "Require codePointString for stable Python/Pydantic string-length parity",
        },
        messages: {
          native:
            "Use codePointString for explicit Python/Pydantic parity across Zod versions.",
        },
        schema: [],
        type: "problem",
      },
    },
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
const noUnsafeRules = Object.fromEntries(
  Object.keys(typescriptEslint.plugin.rules)
    .filter((name) => name.startsWith("no-unsafe-"))
    .map((name) => [`@typescript-eslint/${name}`, "error"]),
);

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
      ...noUnsafeRules,
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
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/no-unsafe-type-assertion": "error",
      "@typescript-eslint/consistent-indexed-object-style": [
        "error",
        "record",
      ],
      "@typescript-eslint/consistent-type-definitions": ["error", "interface"],
      "@typescript-eslint/no-empty-object-type": [
        "error",
        { allowInterfaces: "with-single-extends" },
      ],
      "@typescript-eslint/promise-function-async": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "task1/no-native-zod-string-length": "error",
      "task1/no-jsdoc-any": "error",
    },
  },
);
