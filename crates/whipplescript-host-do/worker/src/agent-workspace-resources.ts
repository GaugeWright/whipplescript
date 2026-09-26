/** Keep a v1 Agent's published definition read-only in its session copy.
 *
 * The admitted root resource is still readable. Its write authority is
 * attenuated to the two run-owned directories; no new resource handle is
 * minted, and every writable selector stays inside its admitted root.
 */
export function agentWorkspaceResources(
  manifest: string,
  resources: unknown,
): Array<Record<string, unknown>> | undefined {
  const admitted = Array.isArray(resources) && resources.length > 0
    ? resources as Array<Record<string, unknown>>
    : undefined;
  if (JSON.parse(manifest).schema !== "whipplescript.agent_package.v1") {
    return admitted;
  }
  // A v1 turn without admitted resources must not get the executor's legacy
  // whole-workspace fallback. An empty scope keeps chat available with no
  // file-tool access.
  if (!admitted) return [];
  return admitted.flatMap((resource) => {
    if (resource.kind !== "file_store" || resource.writable === false) {
      return [resource];
    }
    const selector = resource.selector;
    const root = typeof selector === "string" && selector !== "."
      ? selector.replace(/^\.\//, "").replace(/\/$/, "")
      : "";
    const writable = ["artifacts", "work"].flatMap((allowed) => {
      if (root === "" || allowed.startsWith(`${root}/`) || root === allowed) {
        return [{ ...resource, selector: allowed, writable: true }];
      }
      if (root.startsWith(`${allowed}/`)) {
        return [{ ...resource, writable: true }];
      }
      return [];
    });
    return [{ ...resource, writable: false }, ...writable];
  });
}
