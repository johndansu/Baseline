const path = require('node:path');

function mapPlatform(platform) {
  switch (platform) {
    case 'win32':
      return 'windows';
    case 'linux':
      return 'linux';
    case 'darwin':
      return 'darwin';
    default:
      throw new Error(`Unsupported platform for baselineprod-cli: ${platform}`);
  }
}

function mapArch(arch) {
  switch (arch) {
    case 'x64':
      return 'amd64';
    case 'arm64':
      return 'arm64';
    default:
      throw new Error(`Unsupported architecture for baselineprod-cli: ${arch}`);
  }
}

function resolveTarget(platform, arch) {
  return {
    platform: mapPlatform(platform),
    arch: mapArch(arch)
  };
}

function releaseTagForPackageVersion(version) {
  const trimmed = String(version || '').trim();
  if (!trimmed) {
    throw new Error('Package version is required to resolve the release tag.');
  }
  return trimmed.startsWith('v') ? trimmed : `v${trimmed}`;
}

function archiveExtension(target) {
  return target.platform === 'windows' ? '.zip' : '.tar.gz';
}

function assetNameFor(tag, target) {
  return `baseline_${tag}_${target.platform}_${target.arch}${archiveExtension(target)}`;
}

function binaryFileName(target) {
  return target.platform === 'windows' ? 'baseline.exe' : 'baseline';
}

function installedBinaryPath(packageRoot, target) {
  return path.join(packageRoot, 'vendor', binaryFileName(target));
}

function buildDownloadPlan({
  packageVersion,
  releaseRepo,
  env = process.env,
  platform = process.platform,
  arch = process.arch
}) {
  const target = resolveTarget(platform, arch);
  const tag = String(env.BASELINE_NPM_RELEASE_TAG || releaseTagForPackageVersion(packageVersion)).trim();
  const baseURL = String(
    env.BASELINE_NPM_RELEASE_BASE_URL || `https://github.com/${releaseRepo}/releases/download/${tag}`
  ).replace(/\/+$/, '');
  const assetName = assetNameFor(tag, target);

  return {
    target,
    tag,
    assetName,
    assetURL: `${baseURL}/${assetName}`,
    binaryName: binaryFileName(target)
  };
}

module.exports = {
  archiveExtension,
  assetNameFor,
  binaryFileName,
  buildDownloadPlan,
  installedBinaryPath,
  mapArch,
  mapPlatform,
  releaseTagForPackageVersion,
  resolveTarget
};
