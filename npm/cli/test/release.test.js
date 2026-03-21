const test = require('node:test');
const assert = require('node:assert/strict');
const {
  assetNameFor,
  buildDownloadPlan,
  mapArch,
  mapPlatform,
  releaseTagForPackageVersion,
  resolveTarget
} = require('../lib/release');

test('platform and architecture mapping matches release targets', () => {
  assert.equal(mapPlatform('win32'), 'windows');
  assert.equal(mapPlatform('linux'), 'linux');
  assert.equal(mapPlatform('darwin'), 'darwin');
  assert.equal(mapArch('x64'), 'amd64');
  assert.equal(mapArch('arm64'), 'arm64');
  assert.deepEqual(resolveTarget('linux', 'x64'), { platform: 'linux', arch: 'amd64' });
});

test('release tag adds v prefix when package version is plain semver', () => {
  assert.equal(releaseTagForPackageVersion('1.2.3'), 'v1.2.3');
  assert.equal(releaseTagForPackageVersion('v1.2.3'), 'v1.2.3');
});

test('asset naming matches packaged release archives', () => {
  assert.equal(
    assetNameFor('v1.2.3', { platform: 'windows', arch: 'amd64' }),
    'baseline_v1.2.3_windows_amd64.zip'
  );
  assert.equal(
    assetNameFor('v1.2.3', { platform: 'darwin', arch: 'arm64' }),
    'baseline_v1.2.3_darwin_arm64.tar.gz'
  );
});

test('download plan honors env overrides for release source', () => {
  const plan = buildDownloadPlan({
    packageVersion: '1.2.3',
    releaseRepo: 'johndansu/Baseline',
    env: {
      BASELINE_NPM_RELEASE_TAG: 'v9.9.9',
      BASELINE_NPM_RELEASE_BASE_URL: 'https://example.com/releases/v9.9.9'
    },
    platform: 'linux',
    arch: 'arm64'
  });

  assert.equal(plan.tag, 'v9.9.9');
  assert.equal(plan.assetName, 'baseline_v9.9.9_linux_arm64.tar.gz');
  assert.equal(plan.assetURL, 'https://example.com/releases/v9.9.9/baseline_v9.9.9_linux_arm64.tar.gz');
});
