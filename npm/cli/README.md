# baseline-cli

Installs the compiled Baseline CLI from GitHub release binaries and exposes it as:

```bash
baseline
```

Install globally:

```bash
npm i -g baseline-cli
```

After install:

```bash
baseline version
baseline dashboard login --api https://baseline-api-95nb.onrender.com
```

## Publishing Notes

This npm package is a wrapper around the release archives published from this repository.

Expected release assets:

- `baseline_v<version>_windows_amd64.zip`
- `baseline_v<version>_windows_arm64.zip`
- `baseline_v<version>_linux_amd64.tar.gz`
- `baseline_v<version>_linux_arm64.tar.gz`
- `baseline_v<version>_darwin_amd64.tar.gz`
- `baseline_v<version>_darwin_arm64.tar.gz`

Before publishing a new npm version:

1. publish the matching GitHub Release assets first
2. set this package version to the same semantic version without the `v` prefix
3. run `npm publish`

For example:

- GitHub release tag: `v1.2.3`
- npm package version: `1.2.3`

## Development

Skip the release download during local package installs with:

```bash
BASELINE_NPM_SKIP_DOWNLOAD=1 npm install
```
