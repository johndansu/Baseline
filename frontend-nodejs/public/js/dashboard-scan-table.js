export function renderScansPage(dashboard, filtered, start, end, pageItems, totalPages) {
    const tableBody = document.getElementById('scans-table-body');
    if (tableBody) {
        if (!pageItems.length) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="px-6 py-6 text-sm text-gray-500 text-center">No scans found for the selected filters.</td>
                </tr>
            `;
        } else {
            tableBody.innerHTML = pageItems.map(scan => {
                const status = dashboard.normalizeScanStatus(scan.status);
                const failureDetails = status === 'fail'
                    ? `${scan.blocking_violations} blocking, ${scan.warnings} warnings${scan.first_violation ? ` - ${dashboard.escapeHtml(scan.first_violation)}` : ''}`
                    : '-';
                return `
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${dashboard.escapeHtml(scan.project_name)}</td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="px-2 py-1 text-xs rounded-full ${dashboard.statusBadgeClass(status)}">${dashboard.escapeHtml(status.toUpperCase())}</span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${scan.violations}</td>
                        <td class="px-6 py-4 text-sm text-gray-700">${failureDetails}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${dashboard.formatDate(scan.created_at)}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                            <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700 mr-2" data-scan-id="${dashboard.escapeHtml(scan.id)}" data-format="json">JSON</button>
                            <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700 mr-2" data-scan-id="${dashboard.escapeHtml(scan.id)}" data-format="text">Text</button>
                            <button type="button" class="scan-report-btn text-orange-600 hover:text-orange-700" data-scan-id="${dashboard.escapeHtml(scan.id)}" data-format="sarif">SARIF</button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    }

    dashboard.bindScanReportButtons();

    const meta = document.getElementById('scans-page-meta');
    if (meta) {
        const from = filtered.length === 0 ? 0 : start + 1;
        const to = Math.min(end, filtered.length);
        meta.textContent = `Showing ${from}-${to} of ${filtered.length} scans`;
    }

    const prevBtn = document.getElementById('scans-prev-page');
    const nextBtn = document.getElementById('scans-next-page');
    if (prevBtn) prevBtn.disabled = dashboard.scanState.page <= 1;
    if (nextBtn) nextBtn.disabled = dashboard.scanState.page >= totalPages;
}
