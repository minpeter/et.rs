import { tegami, type TegamiPlugin } from "tegami";
import { runCli } from "tegami/cli";
import { cargo } from "tegami/plugins/cargo";
import { github } from "tegami/plugins/github";

// et.rs ships a single binary crate (`et`). Every crate inherits
// `workspace.package.version`, so bumping `et` bumps the whole workspace.
//
// Releases are git tags (`et@x.y.z`) + GitHub releases only; nothing is
// published to crates.io. Binaries are built and attached to the GitHub
// release by .github/workflows/release.yml.

// Keep the Cargo plugin for manifest versioning and Cargo.lock updates,
// but strip its crates.io publish behavior (preflight, `cargo publish`,
// and the crates.io "is it published yet?" status check).
const cargoPlugin = cargo();
delete cargoPlugin.publishPreflight;
delete cargoPlugin.publish;
delete cargoPlugin.resolvePlanStatus;

// Mark `et` as publishable with a no-op publish, so the github plugin
// still creates the git tag and the GitHub release for it.
function githubReleaseOnly(): TegamiPlugin {
  return {
    name: "github-release-only",
    enforce: "pre",
    publishPreflight({ pkg }) {
      if (pkg.name !== "et") return;
      return { shouldPublish: true };
    },
    async publish({ pkg }) {
      if (pkg.name !== "et") return;
      // No registry to publish to; tag + release are handled by plugins,
      // binaries by CI.
      return { type: "published" as const };
    },
  };
}

const paper = tegami({
  // Internal library crates follow the workspace version automatically;
  // only `et` shows up in changelogs and releases.
  ignore: [/^et-/],
  plugins: [
    githubReleaseOnly(),
    cargoPlugin,
    github({
      repo: "minpeter/et.rs",
      versionPr: {
        base: "main",
      },
    }),
  ],
});

await runCli(paper);
