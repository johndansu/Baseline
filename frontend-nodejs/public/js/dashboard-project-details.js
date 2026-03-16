import { closeModal, openModal } from './dashboard-modal-actions.js';

export async function openProjectDetailsModal(dashboard, projectID) {
    const normalizedID = String(projectID || '').trim();
    if (!normalizedID) {
        dashboard.showError('Invalid project selected.');
        return;
    }
    const project = dashboard.projectState.byID.get(normalizedID);
    if (!project) {
        dashboard.showError('Project details not loaded yet.');
        return;
    }

    dashboard.pendingProjectDetailsID = normalizedID;
    dashboard.projectDetailsRequestToken = Number(dashboard.projectDetailsRequestToken || 0) + 1;
    const requestToken = dashboard.projectDetailsRequestToken;
    setProjectDetailsContent(dashboard, '<div class="text-sm text-gray-600">Loading project summary...</div>');
    openModal('projectDetailsModal');

    try {
        const payload = await dashboard.apiRequest(`/v1/scans?project_id=${encodeURIComponent(normalizedID)}`);
        if (dashboard.pendingProjectDetailsID !== normalizedID || dashboard.projectDetailsRequestToken !== requestToken) {
            return;
        }
        const scans = Array.isArray(payload?.scans) ? payload.scans : [];
        scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        dashboard.projectState.scansByProject.set(normalizedID, scans);
        setProjectDetailsContent(dashboard, renderProjectDetails(dashboard, project, scans));
    } catch (error) {
        if (dashboard.pendingProjectDetailsID !== normalizedID || dashboard.projectDetailsRequestToken !== requestToken) {
            return;
        }
        setProjectDetailsContent(dashboard, `
            <div class="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                ${dashboard.escapeHtml(error.message || 'Failed to load project summary.')}
            </div>
        `);
    }
}

export function setProjectDetailsContent(dashboard, markup) {
    const body = document.getElementById('projectDetailsBody');
    if (body) {
        body.innerHTML = markup;
    }

    const openScansButton = document.getElementById('projectDetailsOpenScansButton');
    if (openScansButton) {
        openScansButton.onclick = () => {
            closeModal('projectDetailsModal');
            dashboard.switchTab('scans');
        };
    }
}

export function renderProjectDetails(dashboard, project, scans) {
    const totalScans = scans.length;
    const failingScans = scans.filter((scan) => dashboard.normalizeScanStatus(scan?.status || '') === 'fail').length;
    const latestScan = scans[0] || null;
    const latestStatus = dashboard.normalizeScanStatus(latestScan?.status || '') || 'unknown';
    const latestViolations = Array.isArray(latestScan?.violations) ? latestScan.violations : [];
    const totalViolations = scans.reduce((sum, scan) => sum + (Array.isArray(scan?.violations) ? scan.violations.length : 0), 0);
    const recentScans = scans.slice(0, 2);
    const latestCommit = String(latestScan?.commit_sha || '').trim();
    const latestCommitDisplay = latestCommit ? latestCommit.slice(0, 12) : 'Not provided';
    const latestFilesScanned = Number(latestScan?.files_scanned || 0);
    const latestScanTime = latestScan ? dashboard.formatDate(latestScan.created_at) : 'No scans yet';
    const scanSummary = totalScans === 0
        ? 'No scans uploaded yet.'
        : failingScans > 0
            ? `${failingScans} of ${totalScans} scans failed.`
            : `All ${totalScans} scans passed.`;
    const latestSummary = latestScan
        ? [
            latestStatus.toUpperCase(),
            latestScanTime,
            latestCommit ? `Commit ${latestCommitDisplay}` : '',
            latestFilesScanned > 0 ? `${latestFilesScanned} files` : '',
            latestViolations.length > 0 ? `${latestViolations.length} violations` : 'No violations'
        ].filter(Boolean).join(' | ')
        : 'No scan details available.';

    return `
        <div class="flex items-start justify-between gap-3">
            <div>
                <h4 class="text-base font-bold text-gray-900">${dashboard.escapeHtml(project.name)}</h4>
                <p class="mt-1 text-sm text-gray-600">${dashboard.escapeHtml(project.repository_url || 'Repository URL not set')}</p>
                <p class="mt-1 text-sm text-gray-700">${dashboard.escapeHtml(scanSummary)}</p>
                <div class="mt-2 flex flex-wrap gap-2 text-xs">
                    <span class="inline-flex items-center rounded-full bg-gray-100 px-2 py-1 text-gray-700">${dashboard.escapeHtml(project.default_branch || 'main')}</span>
                </div>
            </div>
            <span class="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${dashboard.statusBadgeClass(latestStatus)}">${dashboard.escapeHtml(latestStatus.toUpperCase())}</span>
        </div>

        <div class="grid grid-cols-2 gap-2">
            <div class="rounded-lg bg-gray-50 p-2.5">
                <p class="text-xs text-gray-600">Scans</p>
                <p class="mt-1 text-lg font-bold text-gray-900">${totalScans}</p>
            </div>
            <div class="rounded-lg bg-gray-50 p-2.5">
                <p class="text-xs text-gray-600">Files scanned</p>
                <p class="mt-1 text-lg font-bold text-gray-900">${latestScan ? latestFilesScanned : 'Not recorded'}</p>
            </div>
            <div class="rounded-lg bg-gray-50 p-2.5">
                <p class="text-xs text-gray-600">Failures</p>
                <p class="mt-1 text-lg font-bold text-gray-900">${failingScans}</p>
            </div>
            <div class="rounded-lg bg-gray-50 p-2.5">
                <p class="text-xs text-gray-600">Violations</p>
                <p class="mt-1 text-lg font-bold text-gray-900">${totalViolations}</p>
            </div>
        </div>

        <div class="rounded-lg border border-gray-200 p-3">
            <p class="text-sm text-gray-700">${dashboard.escapeHtml(latestSummary)}</p>
        </div>

        <div class="rounded-lg border border-gray-200 p-3">
            <h5 class="text-xs font-semibold uppercase tracking-wide text-gray-500">Recent scans</h5>
            ${recentScans.length ? `
                <div class="mt-2 space-y-1.5">
                    ${recentScans.map((scan) => {
                        const status = dashboard.normalizeScanStatus(scan?.status || '') || 'unknown';
                        const violations = Array.isArray(scan?.violations) ? scan.violations.length : 0;
                        const commit = String(scan?.commit_sha || '').trim();
                        const commitDisplay = commit ? commit.slice(0, 12) : 'No commit';
                        const filesScanned = Number(scan?.files_scanned || 0);
                        return `
                            <div class="flex items-center justify-between gap-3 rounded-lg bg-gray-50 px-2.5 py-2 text-sm">
                                <div>
                                    <p class="font-medium text-gray-900">${dashboard.escapeHtml(commitDisplay)}</p>
                                    <p class="text-xs text-gray-500">${dashboard.escapeHtml(dashboard.formatDate(scan.created_at))}${filesScanned > 0 ? ` | ${filesScanned} files` : ''}</p>
                                </div>
                                <div class="text-right">
                                    <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${dashboard.statusBadgeClass(status)}">${dashboard.escapeHtml(status.toUpperCase())}</span>
                                    <p class="mt-1 text-xs text-gray-600">${violations === 0 ? 'Clean' : `${violations} issues`}</p>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            ` : `
                <p class="mt-2 text-sm text-gray-600">No recent scans available.</p>
            `}
        </div>
    `;
}
