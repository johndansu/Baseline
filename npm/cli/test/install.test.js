const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  findExtractedBinary,
  readInstallMetadata,
  shouldReuseInstalledBinary,
  writeInstallMetadata
} = require('../lib/install');

test('findExtractedBinary finds the extracted executable for unix archives', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'baselineprod-cli-test-'));
  try {
    const binDir = path.join(root, 'pkg');
    await fs.mkdir(binDir, { recursive: true });
    const binary = path.join(binDir, 'baseline_v1.2.3_linux_amd64');
    await fs.writeFile(binary, 'test', 'utf8');
    await fs.writeFile(path.join(binDir, 'RELEASE_INFO.txt'), 'info', 'utf8');

    const resolved = await findExtractedBinary(root, 'linux');
    assert.equal(resolved, binary);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('writeInstallMetadata writes the installed release details', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'baselineprod-cli-test-'));
  try {
    await fs.mkdir(path.join(root, 'vendor'), { recursive: true });
    await writeInstallMetadata(root, {
      tag: 'v1.2.3',
      assetName: 'baseline_v1.2.3_linux_amd64.tar.gz',
      assetURL: 'https://example.com/releases/v1.2.3/baseline_v1.2.3_linux_amd64.tar.gz',
      target: { platform: 'linux', arch: 'amd64' }
    });

    const payload = await readInstallMetadata(root);
    assert.equal(payload.release_tag, 'v1.2.3');
    assert.equal(payload.platform, 'linux');
    assert.equal(payload.arch, 'amd64');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('shouldReuseInstalledBinary returns true for matching installed version metadata', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'baselineprod-cli-test-'));
  try {
    const vendorDir = path.join(root, 'vendor');
    await fs.mkdir(vendorDir, { recursive: true });
    const binaryPath = path.join(vendorDir, 'baseline.exe');
    await fs.writeFile(binaryPath, 'binary', 'utf8');
    await writeInstallMetadata(root, {
      tag: 'v1.1.3',
      assetName: 'baseline_v1.1.3_windows_amd64.zip',
      assetURL: 'https://example.com/releases/v1.1.3/baseline_v1.1.3_windows_amd64.zip',
      target: { platform: 'windows', arch: 'amd64' }
    });

    const result = await shouldReuseInstalledBinary(root, binaryPath, {
      tag: 'v1.1.3',
      assetName: 'baseline_v1.1.3_windows_amd64.zip'
    });

    assert.equal(result, true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('shouldReuseInstalledBinary returns false when metadata does not match', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'baselineprod-cli-test-'));
  try {
    const vendorDir = path.join(root, 'vendor');
    await fs.mkdir(vendorDir, { recursive: true });
    const binaryPath = path.join(vendorDir, 'baseline.exe');
    await fs.writeFile(binaryPath, 'binary', 'utf8');
    await writeInstallMetadata(root, {
      tag: 'v1.1.2',
      assetName: 'baseline_v1.1.2_windows_amd64.zip',
      assetURL: 'https://example.com/releases/v1.1.2/baseline_v1.1.2_windows_amd64.zip',
      target: { platform: 'windows', arch: 'amd64' }
    });

    const result = await shouldReuseInstalledBinary(root, binaryPath, {
      tag: 'v1.1.3',
      assetName: 'baseline_v1.1.3_windows_amd64.zip'
    });

    assert.equal(result, false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
