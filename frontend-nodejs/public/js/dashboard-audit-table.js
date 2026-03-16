export function renderAuditTable(dashboard, events) {
    const auditTab = document.getElementById('audit-tab');
    if (!auditTab) return;

    if (!Array.isArray(events) || events.length === 0) {
        auditTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6">
                <h3 class="text-lg font-semibold text-gray-900">Audit Log</h3>
                <p class="text-sm text-gray-700 mt-1">No audit events found.</p>
            </div>
        `;
        return;
    }

    auditTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200">
            <div class="p-6 border-b border-gray-200">
                <h3 class="text-lg font-semibold text-gray-900">Audit Log</h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${events.map(event => `
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${dashboard.formatDate(event.created_at)}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${dashboard.escapeHtml(event.event_type || '-')}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${dashboard.escapeHtml(event.project_id || '-')}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${dashboard.escapeHtml(event.scan_id || '-')}</td>
                                <td class="px-6 py-4 text-sm text-gray-700">${dashboard.escapeHtml(dashboard.describeAuditEvent(event))}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}
