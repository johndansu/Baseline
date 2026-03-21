const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const AdmZip = require('adm-zip');
const tar = require('tar');
const { buildDownloadPlan, installedBinaryPath } = require('./release');

async function installReleaseBinary(packageRoot, options = {}) {
  const env = options.env || process.env;
  const log = options.log || console.log;
  if (String(env.BASELINE_NPM_SKIP_DOWNLOAD || '').trim() === '1') {
    log('[baseline-cli] Skipping binary download because BASELINE_NPM_SKIP_DOWNLOAD=1.');
    return null;
  }

  const pkg = JSON.parse(await fsp.readFile(path.join(packageRoot, 'package.json'), 'utf8'));
  const releaseRepo = String(pkg?.baseline?.releaseRepo || '').trim();
  if (!releaseRepo) {
    throw new Error('baseline.releaseRepo is missing from package.json.');
  }

  const plan = buildDownloadPlan({
    packageVersion: pkg.version,
    releaseRepo,
    env
  });

  const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'baseline-cli-'));
  const archivePath = path.join(tempRoot, plan.assetName);
  const extractDir = path.join(tempRoot, 'extract');
  await fsp.mkdir(extractDir, { recursive: true });

  try {
    log(`[baseline-cli] Downloading ${plan.assetName}...`);
    await downloadToFile(plan.assetURL, archivePath);
    await extractArchive(archivePath, extractDir, plan.target.platform);
    const extractedBinary = await findExtractedBinary(extractDir, plan.target.platform);
    const destination = installedBinaryPath(packageRoot, plan.target);
    await fsp.mkdir(path.dirname(destination), { recursive: true });
    await fsp.copyFile(extractedBinary, destination);
    if (plan.target.platform !== 'windows') {
      await fsp.chmod(destination, 0o755);
    }
    await writeInstallMetadata(packageRoot, plan);
    log(`[baseline-cli] Installed ${plan.binaryName}.`);
    return destination;
  } finally {
    await fsp.rm(tempRoot, { recursive: true, force: true });
  }
}

function downloadToFile(url, destination, redirectCount = 0) {
  if (redirectCount > 5) {
    return Promise.reject(new Error('Too many redirects while downloading the Baseline release.'));
  }

  const client = url.startsWith('https:') ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.get(url, {
      headers: {
        'User-Agent': 'baseline-cli-installer'
      }
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        downloadToFile(response.headers.location, destination, redirectCount + 1).then(resolve, reject);
        return;
      }

      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Failed to download Baseline release asset (${response.statusCode}).`));
        return;
      }

      const file = fs.createWriteStream(destination);
      response.pipe(file);
      file.on('finish', () => {
        file.close(resolve);
      });
      file.on('error', (error) => {
        file.close(() => reject(error));
      });
    });

    request.on('error', reject);
  });
}

async function extractArchive(archivePath, extractDir, platform) {
  if (platform === 'windows') {
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(extractDir, true);
    return;
  }
  await tar.x({
    file: archivePath,
    cwd: extractDir,
    gzip: true
  });
}

async function findExtractedBinary(rootDir, platform) {
  const entries = await walk(rootDir);
  const candidates = entries.filter((entry) => {
    const base = path.basename(entry).toLowerCase();
    if (!base.startsWith('baseline')) {
      return false;
    }
    if (base.endsWith('.txt') || base.endsWith('.md')) {
      return false;
    }
    if (platform === 'windows') {
      return base.endsWith('.exe');
    }
    return !base.endsWith('.exe');
  });

  if (!candidates.length) {
    throw new Error('Baseline binary not found in the downloaded release archive.');
  }

  candidates.sort();
  return candidates[0];
}

async function walk(rootDir) {
  const result = [];
  const entries = await fsp.readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      result.push(...await walk(fullPath));
      continue;
    }
    result.push(fullPath);
  }
  return result;
}

async function writeInstallMetadata(packageRoot, plan) {
  const metadataPath = path.join(packageRoot, 'vendor', 'install.json');
  const payload = {
    installed_at: new Date().toISOString(),
    release_tag: plan.tag,
    asset_name: plan.assetName,
    asset_url: plan.assetURL,
    platform: plan.target.platform,
    arch: plan.target.arch
  };
  await fsp.writeFile(metadataPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

module.exports = {
  downloadToFile,
  extractArchive,
  findExtractedBinary,
  installReleaseBinary,
  writeInstallMetadata
};
