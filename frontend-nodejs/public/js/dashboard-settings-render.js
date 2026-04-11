export function renderSettingsActionButton(dashboard, label, options = {}, primary = false) {
    const baseClasses = primary
        ? 'inline-flex items-center justify-center rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-black hover:bg-orange-700'
        : 'inline-flex items-center justify-center rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50';
    const actionAttributes = options.tab
        ? `data-settings-nav="${dashboard.escapeHtml(options.tab)}"`
        : options.url
            ? `data-settings-url="${dashboard.escapeHtml(options.url)}"`
            : '';
    return `
        <button
            type="button"
            class="${baseClasses}"
            ${actionAttributes}
        >
            ${dashboard.escapeHtml(label)}
        </button>
    `;
}

export function renderCLISessionsList(dashboard, sessions = [], isLoading = false, errorMessage = '') {
    if (isLoading) {
        return '<div class="rounded-lg border border-dashed border-gray-300 bg-gray-50 px-4 py-5 text-sm text-gray-500">Loading active CLI sessions...</div>';
    }
    if (errorMessage) {
        return `<div class="rounded-lg border border-red-200 bg-red-50 px-4 py-5 text-sm text-red-700">${dashboard.escapeHtml(errorMessage)}</div>`;
    }
    if (!Array.isArray(sessions) || sessions.length === 0) {
        return '<div class="rounded-lg border border-dashed border-gray-300 bg-gray-50 px-4 py-5 text-sm text-gray-500">No active CLI sessions are connected right now.</div>';
    }
    return `
        <div class="space-y-3">
            ${sessions.map((session) => {
                const sessionID = String(session?.session_id || '').trim();
                const clientName = dashboard.escapeHtml(session?.client_name || 'CLI client');
                const clientHost = dashboard.escapeHtml(session?.client_host || 'Unknown host');
                const userLabel = dashboard.escapeHtml(session?.user || 'Unknown user');
                const email = dashboard.escapeHtml(session?.email || '');
                const role = String(session?.role || 'viewer').trim().toLowerCase();
                const roleBadge = dashboard.roleBadgeClass(role);
                const lastUsed = session?.last_used_at ? dashboard.formatDate(session.last_used_at) : 'Unknown';
                const refreshExpiry = session?.refresh_expires_at ? dashboard.formatDate(session.refresh_expires_at) : 'Unknown';
                const cliVersion = dashboard.escapeHtml(session?.cli_version || 'Unknown version');
                const lastRepository = dashboard.escapeHtml(session?.last_repository || 'Not yet reported');
                const lastProjectID = dashboard.escapeHtml(session?.last_project_id || 'Not yet reported');
                const lastIP = dashboard.escapeHtml(session?.last_ip || 'Unknown IP');
                const lastCommand = dashboard.escapeHtml(session?.last_command || 'Not yet reported');
                const lastScanID = dashboard.escapeHtml(session?.last_scan_id || 'Not yet reported');
                const ownerKey = String(session?.owner_key || '').trim();
                return `
                    <div class="rounded-xl border border-gray-200 bg-white px-4 py-4">
                        <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                            <div class="min-w-0">
                                <div class="flex flex-wrap items-center gap-2">
                                    <h5 class="text-sm font-semibold text-gray-900">${clientName}</h5>
                                    <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${roleBadge}">${dashboard.escapeHtml(role)}</span>
                                </div>
                                <p class="mt-1 text-sm text-gray-700">${userLabel}${email ? ` <span class="text-gray-500">(${email})</span>` : ''}</p>
                                <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
                                    <span>Host: ${clientHost}</span>
                                    <span>IP: ${lastIP}</span>
                                    <span>CLI: ${cliVersion}</span>
                                    <span>Last used: ${dashboard.escapeHtml(lastUsed)}</span>
                                    <span>Refresh expires: ${dashboard.escapeHtml(refreshExpiry)}</span>
                                </div>
                                <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
                                    <span>Repository: ${lastRepository}</span>
                                    <span>Project: ${lastProjectID}</span>
                                    <span>Command: ${lastCommand}</span>
                                    <span>Scan: ${lastScanID}</span>
                                </div>
                            </div>
                            <div class="flex flex-col gap-2">
                                <button
                                    type="button"
                                    data-cli-session-view="${dashboard.escapeHtml(sessionID)}"
                                    class="inline-flex items-center justify-center rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                                >
                                    View details
                                </button>
                                <button
                                    type="button"
                                    data-cli-session-revoke="${dashboard.escapeHtml(sessionID)}"
                                    class="inline-flex items-center justify-center rounded-lg border border-red-200 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50"
                                >
                                    Revoke
                                </button>
                                ${ownerKey ? `
                                    <button
                                        type="button"
                                        data-cli-session-revoke-user="${dashboard.escapeHtml(ownerKey)}"
                                        data-cli-session-user-label="${userLabel}"
                                        class="inline-flex items-center justify-center rounded-lg border border-orange-200 px-3 py-2 text-sm font-medium text-orange-700 hover:bg-orange-50"
                                    >
                                        Revoke all for user
                                    </button>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

export function renderSettingsPanel(dashboard) {
    const profileName = dashboard.escapeHtml(dashboard.identity?.displayName || '');
    const email = dashboard.escapeHtml(dashboard.identity?.email || '');
    const role = dashboard.escapeHtml(String(dashboard.authz?.role || 'viewer'));
    const identitySource = String(dashboard.identity?.identitySource || '').trim().toLowerCase();
    const canChangePassword = identitySource === 'supabase';
    const preferences = dashboard.loadDashboardPreferences();

    const accountSummary = `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900">Account</h3>
                    <p class="mt-1 text-sm text-gray-600">Signed-in identity and current access level.</p>
                </div>
                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700">${role}</span>
            </div>
            <dl class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                    <dt class="text-gray-500">Display name</dt>
                    <dd class="mt-1 font-medium text-gray-900">${profileName || 'Not set'}</dd>
                </div>
                <div>
                    <dt class="text-gray-500">Email</dt>
                    <dd class="mt-1 font-medium text-gray-900">${email || 'Not available'}</dd>
                </div>
            </dl>
        </div>
    `;

    const profileEditor = `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h4 class="text-base font-semibold text-gray-900">Profile</h4>
                    <p class="mt-1 text-sm text-gray-600">Update how your name appears in the dashboard.</p>
                </div>
                <span id="settings-profile-feedback" class="text-xs text-gray-500"></span>
            </div>
            <div class="mt-4">
                <label for="settings-display-name" class="block text-sm font-medium text-gray-700 mb-1">Display name</label>
                <input
                    id="settings-display-name"
                    type="text"
                    maxlength="120"
                    autocomplete="name"
                    class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                    value="${profileName}"
                    placeholder="Your name"
                >
            </div>
            <div class="pt-3">
                <button id="settings-profile-save" type="button" class="w-full px-4 py-3 rounded-lg text-sm font-medium shadow-sm" style="background-color:#ea580c;color:#ffffff;">Save name</button>
            </div>
        </div>
    `;

    const preferenceEditor = `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h4 class="text-base font-semibold text-gray-900">Dashboard preferences</h4>
                    <p class="mt-1 text-sm text-gray-600">Choose your default tab and refresh behavior.</p>
                </div>
                <span id="settings-preferences-feedback" class="text-xs text-gray-500"></span>
            </div>
            <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label for="settings-default-tab" class="block text-sm font-medium text-gray-700 mb-1">Default tab</label>
                    <select id="settings-default-tab" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="overview"${preferences.defaultTab === 'overview' ? ' selected' : ''}>Dashboard</option>
                        <option value="scans"${preferences.defaultTab === 'scans' ? ' selected' : ''}>Scan History</option>
                        <option value="projects"${preferences.defaultTab === 'projects' ? ' selected' : ''}>Projects</option>
                        <option value="keys"${preferences.defaultTab === 'keys' ? ' selected' : ''}>API Keys</option>
                        <option value="audit"${preferences.defaultTab === 'audit' ? ' selected' : ''}>Audit Log</option>
                        <option value="settings"${preferences.defaultTab === 'settings' ? ' selected' : ''}>Settings</option>
                    </select>
                </div>
                <div>
                    <label for="settings-refresh-interval" class="block text-sm font-medium text-gray-700 mb-1">Refresh fallback</label>
                    <select id="settings-refresh-interval" class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="30000"${preferences.refreshIntervalMs === 30000 ? ' selected' : ''}>30 seconds</option>
                        <option value="60000"${preferences.refreshIntervalMs === 60000 ? ' selected' : ''}>60 seconds</option>
                        <option value="120000"${preferences.refreshIntervalMs === 120000 ? ' selected' : ''}>120 seconds</option>
                    </select>
                </div>
            </div>
            <div class="mt-4 flex flex-col gap-3">
                <button id="settings-preferences-save" type="button" class="w-full px-4 py-3 rounded-lg text-sm font-medium shadow-sm" style="background-color:#ea580c;color:#ffffff;">Save preferences</button>
                <button id="settings-preferences-reset" type="button" class="w-full px-4 py-3 rounded-lg text-sm font-medium border border-gray-300 text-gray-700 bg-white hover:bg-gray-50">Reset</button>
            </div>
        </div>
    `;

    const passwordEditor = canChangePassword ? `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h4 class="text-base font-semibold text-gray-900">Password</h4>
                    <p class="mt-1 text-sm text-gray-600">Change the password for your sign-in account.</p>
                </div>
                <span id="settings-password-feedback" class="text-xs text-gray-500"></span>
            </div>
            <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label for="settings-new-password" class="block text-sm font-medium text-gray-700 mb-1">New password</label>
                    <input
                        id="settings-new-password"
                        type="password"
                        minlength="8"
                        autocomplete="new-password"
                        class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                        placeholder="At least 8 characters"
                    >
                </div>
                <div>
                    <label for="settings-confirm-password" class="block text-sm font-medium text-gray-700 mb-1">Confirm new password</label>
                    <input
                        id="settings-confirm-password"
                        type="password"
                        minlength="8"
                        autocomplete="new-password"
                        class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                        placeholder="Repeat the new password"
                    >
                </div>
            </div>
            <div class="pt-3">
                <button id="settings-password-save" type="button" class="w-full px-4 py-3 rounded-lg text-sm font-medium shadow-sm" style="background-color:#ea580c;color:#ffffff;">Change password</button>
            </div>
        </div>
    ` : '';

    if (!dashboard.isAdmin()) {
        return `
            <div class="w-full p-6">
                <div class="space-y-5 max-w-4xl">
                    <div>
                        <h2 class="text-2xl font-semibold text-gray-900">Account settings</h2>
                        <p class="mt-1 text-sm text-gray-600">Update your profile and how this dashboard behaves for you.</p>
                    </div>
                    ${accountSummary}
                    <div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
                        ${profileEditor}
                        ${preferenceEditor}
                    </div>
                    ${passwordEditor}
                </div>
            </div>
        `;
    }

    const adminActions = `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h4 class="text-lg font-semibold text-gray-900">Operations</h4>
                    <p class="mt-1 text-sm text-gray-700">Jump to the write surfaces you actually use.</p>
                </div>
                <div class="hidden md:grid grid-cols-2 gap-2 min-w-[220px]">
                    <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                        <p class="text-[10px] uppercase tracking-[0.16em] text-gray-500 font-semibold">Users</p>
                        <p class="mt-1 text-sm font-semibold text-gray-900">Access control</p>
                    </div>
                    <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                        <p class="text-[10px] uppercase tracking-[0.16em] text-gray-500 font-semibold">Projects</p>
                        <p class="mt-1 text-sm font-semibold text-gray-900">Scan control</p>
                    </div>
                </div>
            </div>
            <div class="mt-4 flex flex-wrap gap-2">
                ${renderSettingsActionButton(dashboard, 'Users', { tab: 'users' }, true)}
                ${renderSettingsActionButton(dashboard, 'Projects', { tab: 'projects' })}
                ${renderSettingsActionButton(dashboard, 'API Keys', { tab: 'keys' })}
            </div>
        </div>
    `;

    const cliSessionsPanel = `
        <div class="rounded-xl border border-gray-200 bg-white p-6">
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h4 class="text-lg font-semibold text-gray-900">CLI sessions</h4>
                    <p class="mt-1 text-sm text-gray-700">Review which CLI devices are connected to the dashboard and revoke any session that should stop working.</p>
                </div>
                <div class="flex flex-col items-end gap-2">
                    <button
                        id="settings-cli-approve-button"
                        type="button"
                        class="inline-flex items-center justify-center rounded-lg bg-orange-600 px-3 py-2 text-sm font-medium text-black hover:bg-orange-700"
                        style="background-color:#ea580c;color:#ffffff;"
                    >
                        Approve CLI login
                    </button>
                    <span id="settings-cli-sessions-feedback" class="text-xs text-gray-500"></span>
                </div>
            </div>
            <div id="settings-cli-sessions-list" class="mt-4">
                ${renderCLISessionsList(dashboard, [], true)}
            </div>
        </div>
    `;

    return `
        <div class="w-full p-6">
            <div class="space-y-5 max-w-5xl">
                <div>
                    <h2 class="text-2xl font-semibold text-gray-900">Account settings</h2>
                    <p class="mt-1 text-sm text-gray-600">Update your profile, password, and dashboard preferences.</p>
                </div>
                ${accountSummary}
                <div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
                    ${profileEditor}
                    ${preferenceEditor}
                </div>
                ${passwordEditor}
                ${cliSessionsPanel}
                ${adminActions}
            </div>
        </div>
    `;
}
