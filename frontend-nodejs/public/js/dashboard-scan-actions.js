export function bindScanReportButtons(dashboard, root = document) {
    root.querySelectorAll('.scan-report-btn').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async (event) => {
            event.preventDefault();
            const scanID = String(button.dataset.scanId || button.getAttribute('data-scan-id') || '').trim();
            const format = String(button.dataset.format || button.getAttribute('data-format') || 'json').trim();
            await dashboard.downloadScanReport(scanID, format);
        });
    });
}
