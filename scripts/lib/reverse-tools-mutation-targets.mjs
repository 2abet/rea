import { readFileSync } from "node:fs";
import ts from "typescript6";

/** Resolve a semantic mutation target afresh; missing/ambiguous targets fail closed. */
export const mutationRange = (path, selector) => {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  const found = [];
  const visit = (node) => {
    const matches =
      selector.expression !== undefined
        ? ts.isBinaryExpression(node) &&
          node.getText(source).replace(/\s+/gu, "") ===
            selector.expression.replace(/\s+/gu, "")
        : ts.isVariableDeclaration(node) &&
          node.name.getText(source) === selector.declaration;
    if (matches) found.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source);
  if (found.length !== 1)
    throw new Error(
      `Expected one mutation target in ${path}: ${JSON.stringify(selector)}; found ${found.length}`,
    );
  const node = found[0];
  const first =
    source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
  const last = source.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
  return `${path}:${first}-${last}`;
};
