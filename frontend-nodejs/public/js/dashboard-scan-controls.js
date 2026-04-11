export function renderScansTable(dashboard, scans) {
    const scansTab = document.getElementById('scans-tab');
    if (!scansTab) return;
    const canRunScans = dashboard.hasCapability('scans.run');
    const runScanButton = canRunScans
        ? `<button type="button" data-open-modal="runScanModal" class="px-4 py-2 bg-orange-600 text-black rounded-lg hover:bg-orange-700 text-sm font-medium">Run New Scan</button>`
        : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Run New Scan</button>`;

    const uniqueProjects = Array.from(new Set(scans.map((scan) => scan.project_name))).sort((a, b) => a.localeCompare(b));
    const projectOptions = uniqueProjects
        .map((name) => `<option value="${dashboard.escapeHtml(name)}">${dashboard.escapeHtml(name)}</option>`)
        .join('');

    scansTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200">
            <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900">Scan History</h3>
                    <p class="text-sm text-gray-700 mt-1">Real scan results from the Baseline API</p>
                </div>
                ${runScanButton}
            </div>
            <div class="p-4 border-b border-gray-200 bg-gray-50 flex flex-wrap items-end gap-3">
                <div>
                    <label class="block text-xs font-medium text-gray-600 mb-1">Status</label>
                    <select id="scans-status-filter" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="all">All</option>
                        <option value="pass">Pass</option>
                        <option value="fail">Fail</option>
                        <option value="warn">Warn</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-600 mb-1">Project</label>
                    <select id="scans-project-filter" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="all">All</option>
                        ${projectOptions}
                    </select>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Violations</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Failure Details</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reports</th>
                        </tr>
                    </thead>
                    <tbody id="scans-table-body" class="bg-white divide-y divide-gray-200"></tbody>
                </table>
            </div>
            <div class="p-4 border-t border-gray-200 flex items-center justify-between">
                <p id="scans-page-meta" class="text-sm text-gray-600"></p>
                <div class="flex items-center gap-2">
                    <button id="scans-prev-page" class="px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50">Previous</button>
                    <button id="scans-next-page" class="px-3 py-1.5 border border-gray-300 rounded text-sm hover:bg-gray-50">Next</button>
                </div>
            </div>
        </div>
    `;

    dashboard.bindModalTriggerButtons();
    bindScansControls(dashboard);
    applyScansFiltersAndRender(dashboard);
}

export function bindScansControls(dashboard) {
    const statusFilter = document.getElementById('scans-status-filter');
    const projectFilter = document.getElementById('scans-project-filter');
    const prevBtn = document.getElementById('scans-prev-page');
    const nextBtn = document.getElementById('scans-next-page');

    if (statusFilter && statusFilter.dataset.bound !== '1') {
        statusFilter.dataset.bound = '1';
        statusFilter.value = dashboard.scanState.statusFilter;
        statusFilter.addEventListener('change', () => {
            dashboard.scanState.statusFilter = statusFilter.value || 'all';
            dashboard.scanState.page = 1;
            applyScansFiltersAndRender(dashboard);
        });
    }
    if (projectFilter && projectFilter.dataset.bound !== '1') {
        projectFilter.dataset.bound = '1';
        projectFilter.value = dashboard.scanState.projectFilter;
        projectFilter.addEventListener('change', () => {
            dashboard.scanState.projectFilter = projectFilter.value || 'all';
            dashboard.scanState.page = 1;
            applyScansFiltersAndRender(dashboard);
        });
    }
    if (prevBtn && prevBtn.dataset.bound !== '1') {
        prevBtn.dataset.bound = '1';
        prevBtn.addEventListener('click', () => {
            if (dashboard.scanState.page > 1) {
                dashboard.scanState.page -= 1;
                applyScansFiltersAndRender(dashboard);
            }
        });
    }
    if (nextBtn && nextBtn.dataset.bound !== '1') {
        nextBtn.dataset.bound = '1';
        nextBtn.addEventListener('click', () => {
            const totalPages = Math.max(1, Math.ceil(dashboard.scanState.filtered.length / dashboard.scanState.pageSize));
            if (dashboard.scanState.page < totalPages) {
                dashboard.scanState.page += 1;
                applyScansFiltersAndRender(dashboard);
            }
        });
    }
}

export function applyScansFiltersAndRender(dashboard) {
    let filtered = [...dashboard.scanState.all];
    if (dashboard.scanState.statusFilter !== 'all') {
        filtered = filtered.filter((scan) => dashboard.normalizeScanStatus(scan.status) === dashboard.scanState.statusFilter);
    }
    if (dashboard.scanState.projectFilter !== 'all') {
        filtered = filtered.filter((scan) => scan.project_name === dashboard.scanState.projectFilter);
    }
    dashboard.scanState.filtered = filtered;

    const totalPages = Math.max(1, Math.ceil(filtered.length / dashboard.scanState.pageSize));
    if (dashboard.scanState.page > totalPages) {
        dashboard.scanState.page = totalPages;
    }
    const start = (dashboard.scanState.page - 1) * dashboard.scanState.pageSize;
    const end = start + dashboard.scanState.pageSize;
    const pageItems = filtered.slice(start, end);

    dashboard.renderScansPage(filtered, start, end, pageItems, totalPages);
}
