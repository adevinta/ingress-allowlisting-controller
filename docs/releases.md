# Releases and versions

Releases are git tags `vX.Y.Z` with a GitHub release. The `v` is what Go modules expect
(`go get github.com/adevinta/ingress-allowlisting-controller@v0.1.6`).

## How a release is made

- **Patch releases are automatic.** Every commit on `main` is built (`build images`), and once its
  image is pushed, the `release` job tags the commit with the next patch version (`v0.1.6`,
  `v0.1.7`, …) and creates a GitHub release with notes from the merged PRs. A tag therefore never
  points at a commit without an image.
- **A commit that changes only CI, docs or tests is not released**: when everything changed since
  the last release is under `.github/`, `docs/`, `hack/` or `test/`, or a `*.md`, `*_test.go` or
  `.gitignore` file (`hack/next-release.sh`). Such changes go into the next release that changes
  the image or the chart.
- **A breaking change makes the next minor release automatically** (`v0.1.8` → `v0.2.0`; from
  `v1` on, the next major), so deployments following `v0.1.*` never get it. A change is breaking
  when a commit since the last release is marked so, in its title or in a body line (a squash
  merge lists every commit of the PR):
  - `type!:` or `type(scope)!:` (Conventional Commits), e.g. `fix(cidrs)!: …`,
  - `type(breaking):`, e.g. `feat(breaking): …`,
  - a line starting with `BREAKING`, e.g. `BREAKING: … now defaults to false`.

  Keep the marker when editing the squash commit message (the PR title is the commit title).
  Without it a breaking change is released as a patch.
- **Minor and major releases can also be tags pushed by hand**, on a `main` commit that is
  already released or built, e.g. to start a minor without a breaking change:

  ```bash
  git tag v0.2.0 <commit> && git push origin v0.2.0
  ```

  The workflow adds the image tag and the GitHub release; the next `main` commit becomes `v0.2.1`.

## Images

`ghcr.io/adevinta/ingress-allowlisting-controller` has, for every built commit, `:<commit sha>`;
a released commit also has `:X.Y.Z` (no `v`). `:latest` is the last `main` build.

The image contains the controller binary built with the Go of the Dockerfile's `golang` tag, on
`distroless/static:nonroot`, with the CA bundle of `ubuntu:latest` at build time.

## Security updates

- **Go modules change only for security.** Dependabot opens no version updates for them, only
  security updates for an advisory (repository setting "Dependabot security updates"), to the
  smallest fixing version. `dependabot-automerge` runs govulncheck on the base and on the PR, and
  merges the PR only when it fixes a vulnerability our code calls (reported on the base, gone
  with the PR). A PR for a vulnerability we don't call waits for a human. Fewer and smaller
  dependency changes leave less room for a compromised release.
- **The `golang` builder tag** (Go toolchain and standard library, where most findings are fixed):
  Dependabot proposes updates every Monday, and patch updates merge automatically.
- **GitHub Actions**: Dependabot proposes the updates every Monday in one PR, which waits for a
  review and makes no release.
- Automatic merges go through the merge queue: `dependabot-automerge` approves the PR, the queue
  merges it once `testGo` passes (vet, govulncheck, unit and kind tests).
- A merge started by a workflow token starts no workflow itself, so `release-pending` checks every
  hour that `main` is released and, if not, starts its build (and so its release).
- **govulncheck** also runs on `main` every Monday at 07:00 UTC, for vulnerabilities published
  after the last PR. A failure there means an update is needed.

Rebuilding an unchanged commit gives nothing new (same Go, same modules), so there are no
scheduled rebuilds: an update reaches the image through a commit, and so through a release.

## Argo CD

Follow the patch releases of one minor with a semver constraint on the git tags. A new minor
means breaking changes: read its release notes, then move `targetRevision` to it (`v0.2.*`).

```yaml
spec:
  source:
    repoURL: https://github.com/adevinta/ingress-allowlisting-controller.git
    path: helm-chart/ingress-allowlisting-controller
    targetRevision: v0.1.*
    helm:
      parameters:
        - name: image.fullyQualifiedURL
          value: ghcr.io/adevinta/ingress-allowlisting-controller:$ARGOCD_APP_REVISION
```

Argo CD picks the newest matching tag and renders the chart from its commit;
`$ARGOCD_APP_REVISION` is that commit's SHA, so the image tag is `:<commit sha>`, which exists
for every release. A job that waits for the image (needed with `targetRevision: HEAD`, where Argo
sees a commit before its image is built) is no longer needed.

Argo CD gives the chart the commit SHA only, not the tag name, which is why deployments use the
`:<commit sha>` image tag. `Chart.yaml`'s `version`/`appVersion` are not changed by releases.
