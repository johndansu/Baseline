export function renderApiKeysTable(dashboard, apiKeys) {
    const keysTab = document.getElementById('keys-tab');
    if (!keysTab) return;
    const canWriteKeys = dashboard.hasCapability('api_keys.write');
    const scope = dashboard.resolveAPIKeyScope();
    const adminScopeControls = dashboard.renderAPIKeyScopeControls();
    const scopeLabel = scope.mode === 'user'
        ? `User scope: ${dashboard.escapeHtml(dashboard.apiKeyScopeUserLabel() || 'unknown')}`
        : scope.mode === 'me'
            ? 'My keys: API keys linked to your dashboard user'
            : 'Admin inventory: global key management';
    const canGenerateInScope = canWriteKeys && (scope.mode !== 'user' || String(dashboard.apiKeyState.targetUserID || '').trim() !== '');
    const generateKeyButton = canGenerateInScope
        ? `<button type="button" data-open-modal="generateKeyModal" class="px-4 py-2 bg-orange-600 text-black rounded-lg hover:bg-orange-700 text-sm font-medium" style="background-color:#ea580c;color:#ffffff;">Generate Key</button>`
        : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Generate Key</button>`;
    const actionsHeader = canWriteKeys
        ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>`
        : '';
    const ownerHeader = dashboard.isAdmin()
        ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>`
        : '';

    if (!Array.isArray(apiKeys) || apiKeys.length === 0) {
        keysTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6" style="color:#111827;">
                <div class="flex items-center justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900" style="color:#111827;">API Keys</h3>
                        <p class="text-sm text-gray-700 mt-1" style="color:#374151;">No API keys found.</p>
                    </div>
                    ${generateKeyButton}
                </div>
                ${adminScopeControls}
                <p class="mt-3 text-xs text-gray-500" style="color:#6b7280;">${scopeLabel}</p>
            </div>
        `;
        dashboard.bindModalTriggerButtons(keysTab);
        dashboard.bindAPIKeyScopeControls();
        return;
    }

    keysTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200" style="color:#111827;">
            <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900" style="color:#111827;">API Keys</h3>
                    <p class="text-sm text-gray-700 mt-1" style="color:#374151;">Metadata only. Secrets are never returned after issuance.</p>
                    <p class="text-xs text-gray-500 mt-1" style="color:#6b7280;">${scopeLabel}</p>
                </div>
                ${generateKeyButton}
            </div>
            ${adminScopeControls}
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key ID</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Prefix</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                            ${ownerHeader}
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                            ${actionsHeader}
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${apiKeys.map(key => {
                            const status = key.revoked ? 'revoked' : 'active';
                            const role = String(key.role || 'viewer').toLowerCase();
                            const disableRevoke = key.revoked;
                            return `
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${dashboard.escapeHtml(key.name || 'unnamed')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(key.id || '')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(key.prefix || '-')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${dashboard.roleBadgeClass(role)}">${dashboard.escapeHtml(role)}</span>
                                    </td>
                                    ${dashboard.isAdmin() ? `
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">
                                            ${dashboard.escapeHtml(key.owner_user_id || key.owner_email || key.owner_subject || '-')}
                                        </td>
                                    ` : ''}
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(key.source || '-')}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="px-2 py-1 text-xs rounded-full ${status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">${status}</span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${dashboard.formatDate(key.created_at)}</td>
                                    ${canWriteKeys ? `
                                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                                            ${disableRevoke ? '<span class="text-gray-400">-</span>' : `
                                                <button
                                                    type="button"
                                                    data-key-action="revoke"
                                                    data-key-id="${dashboard.escapeHtml(String(key.id || ''))}"
                                                    class="text-red-600 hover:text-red-700 font-medium"
                                                >
                                                    Revoke
                                                </button>
                                            `}
                                        </td>
                                    ` : ''}
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    dashboard.bindModalTriggerButtons(keysTab);
    dashboard.bindAPIKeyScopeControls();
    dashboard.bindAPIKeyActionButtons(keysTab);
}
