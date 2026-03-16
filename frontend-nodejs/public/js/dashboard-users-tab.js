export function renderUsersTab(dashboard, users, errorMessage = '') {
    const usersTab = document.getElementById('users-tab');
    if (!usersTab) {
        return;
    }

    if (!dashboard.isAdmin()) {
        usersTab.innerHTML = `
            <div class="bg-white rounded-lg border border-amber-200 p-6">
                <h3 class="text-lg font-semibold text-amber-900">Users</h3>
                <p class="text-sm text-amber-700 mt-1">Admin access is required.</p>
            </div>
        `;
        return;
    }

    const userList = Array.isArray(users) ? users : [];
    const filters = dashboard.userState.filters || {};
    const sortBy = String(filters.sortBy || 'updated_at').trim().toLowerCase();
    const sortDir = String(filters.sortDir || 'desc').trim().toLowerCase() === 'asc' ? 'asc' : 'desc';
    const totalCount = Number(dashboard.userState.total || userList.length);
    const limit = Number(dashboard.userState.limit || filters.limit || 100);
    const safeLimit = Number.isFinite(limit) && limit > 0 ? limit : 100;
    const offset = Number(dashboard.userState.offset || 0);
    const safeOffset = Number.isFinite(offset) && offset >= 0 ? offset : 0;
    const safePage = Math.max(1, Math.floor(safeOffset / safeLimit) + 1);
    const totalPages = Math.max(1, Math.ceil(totalCount / safeLimit));
    const start = safeOffset;
    const pageRows = userList;
    const selected = dashboard.userState.selected;
    const selectedActivity = Array.isArray(dashboard.userState.selectedActivity) ? dashboard.userState.selectedActivity : [];
    const selectedActivityFilters = dashboard.userState.selectedActivityFilters || { eventType: '', from: '', to: '' };
    const selectedActivityTypeOptions = dashboard.userActivityEventTypeOptions(selectedActivity, selectedActivityFilters.eventType);
    const selectedActivityRows = selectedActivity.length
        ? selectedActivity.map((event) => `
            <tr>
                <td class="px-3 py-2 text-xs text-gray-700">${dashboard.escapeHtml(dashboard.formatDate(event.created_at))}</td>
                <td class="px-3 py-2 text-xs text-gray-900">${dashboard.escapeHtml(event.event_type || '-')}</td>
                <td class="px-3 py-2 text-xs text-gray-700">${dashboard.escapeHtml(event.project_id || '-')}</td>
                <td class="px-3 py-2 text-xs text-gray-700">${dashboard.escapeHtml(event.scan_id || '-')}</td>
                <td class="px-3 py-2 text-xs text-gray-500">${dashboard.escapeHtml(event.request_id || '-')}</td>
            </tr>
        `).join('')
        : `
            <tr>
                <td colspan="5" class="px-3 py-3 text-xs text-gray-500 text-center">No activity events found for this user.</td>
            </tr>
        `;
    const detailPanel = selected
        ? `
            <div class="mx-6 mt-4 mb-2 rounded-lg border border-blue-200 bg-blue-50 p-4">
                <div class="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                    <div>
                        <h4 class="text-sm font-semibold text-blue-900">Selected User</h4>
                        <p class="mt-1 text-xs text-blue-800">Basic edits are limited to role and status. Identity data stays read-only.</p>
                    </div>
                    <button type="button" id="users-detail-clear" class="text-xs text-blue-700 hover:text-blue-900 font-medium">Clear</button>
                </div>
                <div class="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <p><span class="text-gray-600">ID:</span> <span class="font-mono text-gray-900">${dashboard.escapeHtml(selected.id || '-')}</span></p>
                    <p><span class="text-gray-600">Email:</span> <span class="text-gray-900">${dashboard.escapeHtml(selected.email || '-')}</span></p>
                    <p><span class="text-gray-600">Role:</span> <span class="text-gray-900">${dashboard.escapeHtml(selected.role || '-')}</span></p>
                    <p><span class="text-gray-600">Status:</span> <span class="text-gray-900">${dashboard.escapeHtml(selected.status || '-')}</span></p>
                    <p><span class="text-gray-600">Provider:</span> <span class="text-gray-900">${dashboard.escapeHtml(selected.provider || '-')}</span></p>
                    <p><span class="text-gray-600">Last login:</span> <span class="text-gray-900">${dashboard.escapeHtml(dashboard.formatDate(selected.last_login_at))}</span></p>
                </div>
                <div class="mt-3 rounded-lg border border-blue-200 bg-white p-3">
                    <div class="flex flex-col md:flex-row md:items-end gap-3">
                        <div>
                            <label for="admin-user-detail-role" class="block text-[11px] font-medium uppercase tracking-wide text-gray-500 mb-1">Role</label>
                            <select id="admin-user-detail-role" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                                <option value="viewer"${String(selected.role || '').toLowerCase() === 'viewer' ? ' selected' : ''}>viewer</option>
                                <option value="operator"${String(selected.role || '').toLowerCase() === 'operator' ? ' selected' : ''}>operator</option>
                                <option value="admin"${String(selected.role || '').toLowerCase() === 'admin' ? ' selected' : ''}>admin</option>
                            </select>
                        </div>
                        <div>
                            <label for="admin-user-detail-status" class="block text-[11px] font-medium uppercase tracking-wide text-gray-500 mb-1">Status</label>
                            <select id="admin-user-detail-status" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                                <option value="active"${String(selected.status || '').toLowerCase() === 'active' ? ' selected' : ''}>active</option>
                                <option value="suspended"${String(selected.status || '').toLowerCase() === 'suspended' ? ' selected' : ''}>suspended</option>
                            </select>
                        </div>
                        <div class="flex items-center gap-2 md:ml-auto">
                            <button
                                type="button"
                                class="px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-xs font-medium"
                                data-user-action="save"
                                data-user-id="${dashboard.escapeHtml(String(selected.id || ''))}"
                                data-user-source="detail"
                            >
                                Save Access
                            </button>
                            <button
                                type="button"
                                class="px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-xs font-medium"
                                data-user-action="toggle-status"
                                data-user-id="${dashboard.escapeHtml(String(selected.id || ''))}"
                                data-user-next-status="${String(selected.status || '').toLowerCase() === 'suspended' ? 'active' : 'suspended'}"
                            >
                                ${String(selected.status || '').toLowerCase() === 'suspended' ? 'Activate' : 'Suspend'}
                            </button>
                        </div>
                    </div>
                </div>
                <div class="mt-3 rounded-lg border border-blue-200 bg-white">
                    <div class="px-3 py-2 border-b border-blue-100 flex items-center justify-between">
                        <p class="text-xs font-semibold text-gray-900">Recent Activity</p>
                        <p class="text-[11px] text-gray-500">Showing ${selectedActivity.length} of ${Number(dashboard.userState.selectedActivityTotal || 0)}</p>
                    </div>
                    <div class="px-3 py-2 border-b border-blue-100 bg-blue-50/40">
                        <div class="grid grid-cols-1 md:grid-cols-4 gap-2">
                            <div>
                                <input id="users-activity-filter-event-type" list="users-activity-event-type-list" type="text" value="${dashboard.escapeHtml(selectedActivityFilters.eventType || '')}" placeholder="event_type (optional)" class="w-full px-2 py-1 border border-gray-300 rounded text-xs">
                                <datalist id="users-activity-event-type-list">
                                    ${selectedActivityTypeOptions}
                                </datalist>
                            </div>
                            <input id="users-activity-filter-from" type="datetime-local" value="${dashboard.escapeHtml(selectedActivityFilters.from || '')}" class="px-2 py-1 border border-gray-300 rounded text-xs">
                            <input id="users-activity-filter-to" type="datetime-local" value="${dashboard.escapeHtml(selectedActivityFilters.to || '')}" class="px-2 py-1 border border-gray-300 rounded text-xs">
                            <div class="flex items-center gap-2 justify-start md:justify-end">
                                <button id="users-activity-filter-apply" type="button" class="px-3 py-1.5 bg-blue-700 text-white rounded text-xs hover:bg-blue-800">Apply</button>
                                <button id="users-activity-filter-reset" type="button" class="px-3 py-1.5 border border-gray-300 text-gray-700 rounded text-xs hover:bg-gray-50">Reset</button>
                            </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Time</th>
                                    <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Event</th>
                                    <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Project</th>
                                    <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Scan</th>
                                    <th class="px-3 py-2 text-left text-[10px] font-medium text-gray-500 uppercase tracking-wider">Request ID</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-100">
                                ${selectedActivityRows}
                            </tbody>
                        </table>
                    </div>
                    <div class="px-3 py-2 border-t border-blue-100 flex items-center justify-end">
                        <button id="users-activity-load-more" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${dashboard.userState.selectedActivityHasMore ? 'text-gray-700 hover:bg-gray-50' : 'text-gray-400 bg-gray-100 cursor-not-allowed'}" ${dashboard.userState.selectedActivityHasMore ? '' : 'disabled aria-disabled="true"'}>Load More</button>
                    </div>
                </div>
            </div>
        `
        : '';
    const rows = pageRows.length
        ? pageRows.map((user) => {
            const userID = String(user.id || '').trim();
            const rowKey = dashboard.adminUserRowKey(userID);
            const role = String(user.role || 'viewer').toLowerCase();
            const status = String(user.status || 'active').toLowerCase();
            return `
                <tr>
                    <td class="px-4 py-3 text-sm text-gray-900">${dashboard.escapeHtml(user.email || user.display_name || userID)}</td>
                    <td class="px-4 py-3 text-sm text-gray-700">${dashboard.escapeHtml(userID)}</td>
                    <td class="px-4 py-3">
                        <select id="admin-user-role-${rowKey}" class="px-2 py-1 border border-gray-300 rounded text-sm">
                            <option value="viewer"${role === 'viewer' ? ' selected' : ''}>viewer</option>
                            <option value="operator"${role === 'operator' ? ' selected' : ''}>operator</option>
                            <option value="admin"${role === 'admin' ? ' selected' : ''}>admin</option>
                        </select>
                    </td>
                    <td class="px-4 py-3">
                        <select id="admin-user-status-${rowKey}" class="px-2 py-1 border border-gray-300 rounded text-sm">
                            <option value="active"${status === 'active' ? ' selected' : ''}>active</option>
                            <option value="suspended"${status === 'suspended' ? ' selected' : ''}>suspended</option>
                        </select>
                    </td>
                    <td class="px-4 py-3 text-sm text-gray-700">${dashboard.escapeHtml(dashboard.formatDate(user.last_login_at))}</td>
                    <td class="px-4 py-3 text-sm">
                        <button
                            type="button"
                            class="px-3 py-1 mr-2 border border-gray-300 text-gray-700 rounded hover:bg-gray-50 text-xs font-medium"
                            data-user-action="view"
                            data-user-id="${dashboard.escapeHtml(userID)}"
                        >
                            View
                        </button>
                        <button
                            type="button"
                            class="px-3 py-1 bg-orange-600 text-white rounded hover:bg-orange-700 text-xs font-medium"
                            data-user-action="save"
                            data-user-id="${dashboard.escapeHtml(userID)}"
                            data-user-source="row"
                        >
                            Save Access
                        </button>
                    </td>
                </tr>
            `;
        }).join('')
        : `
            <tr>
                <td colspan="6" class="px-4 py-4 text-sm text-gray-500 text-center">No users found.</td>
            </tr>
        `;

    usersTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200">
            <div class="p-6 border-b border-gray-200">
                <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Users</h3>
                        <p class="text-sm text-gray-700 mt-1">Control role assignment and account status from one place.</p>
                    </div>
                    <div class="grid grid-cols-3 gap-2">
                        <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                            <p class="text-[10px] uppercase tracking-[0.16em] text-gray-500 font-semibold">Total</p>
                            <p class="mt-1 text-lg font-bold text-gray-900">${totalCount}</p>
                        </div>
                        <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                            <p class="text-[10px] uppercase tracking-[0.16em] text-gray-500 font-semibold">Selected</p>
                            <p class="mt-1 text-lg font-bold text-gray-900">${selected ? '1' : '0'}</p>
                        </div>
                        <div class="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                            <p class="text-[10px] uppercase tracking-[0.16em] text-gray-500 font-semibold">Page</p>
                            <p class="mt-1 text-lg font-bold text-gray-900">${safePage}/${totalPages}</p>
                        </div>
                    </div>
                </div>
                <div class="mt-4 grid grid-cols-1 md:grid-cols-5 gap-3">
                    <input id="users-filter-q" type="text" value="${dashboard.escapeHtml(filters.q || '')}" placeholder="Search user/email..." class="md:col-span-2 px-3 py-2 border border-gray-300 rounded-lg text-sm">
                    <select id="users-filter-role" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="all"${String(filters.role || 'all') === 'all' ? ' selected' : ''}>All roles</option>
                        <option value="viewer"${String(filters.role || '') === 'viewer' ? ' selected' : ''}>viewer</option>
                        <option value="operator"${String(filters.role || '') === 'operator' ? ' selected' : ''}>operator</option>
                        <option value="admin"${String(filters.role || '') === 'admin' ? ' selected' : ''}>admin</option>
                    </select>
                    <select id="users-filter-status" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="all"${String(filters.status || 'all') === 'all' ? ' selected' : ''}>All status</option>
                        <option value="active"${String(filters.status || '') === 'active' ? ' selected' : ''}>active</option>
                        <option value="suspended"${String(filters.status || '') === 'suspended' ? ' selected' : ''}>suspended</option>
                    </select>
                    <select id="users-filter-limit" class="px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        <option value="25"${Number(filters.limit || 100) === 25 ? ' selected' : ''}>Limit 25</option>
                        <option value="50"${Number(filters.limit || 100) === 50 ? ' selected' : ''}>Limit 50</option>
                        <option value="100"${Number(filters.limit || 100) === 100 ? ' selected' : ''}>Limit 100</option>
                        <option value="200"${Number(filters.limit || 100) === 200 ? ' selected' : ''}>Limit 200</option>
                    </select>
                </div>
                <div class="mt-3 flex items-center gap-2">
                    <button id="users-filter-apply" type="button" class="px-3 py-1.5 bg-orange-600 text-white rounded hover:bg-orange-700 text-xs font-medium">Apply</button>
                    <button id="users-filter-reset" type="button" class="px-3 py-1.5 border border-gray-300 text-gray-700 rounded hover:bg-gray-50 text-xs font-medium">Reset</button>
                    <span class="text-xs text-gray-500">Showing ${totalCount === 0 ? 0 : start + 1}-${Math.min(start + pageRows.length, totalCount)} of ${totalCount} | Sort: ${userSortDescriptor(sortBy, sortDir)}</span>
                </div>
                <p id="admin-users-feedback" class="mt-2 text-xs ${errorMessage ? 'text-red-600' : 'text-gray-500'}">${dashboard.escapeHtml(errorMessage || 'Edit role or status, then save from the row or the selected user panel.')}</p>
            </div>
            ${detailPanel}
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                <button id="users-sort-user" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                    User <span class="text-[10px]">${userSortIndicator('user', sortBy, sortDir)}</span>
                                </button>
                            </th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User ID</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                <button id="users-sort-role" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                    Role <span class="text-[10px]">${userSortIndicator('role', sortBy, sortDir)}</span>
                                </button>
                            </th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                <button id="users-sort-status" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                    Status <span class="text-[10px]">${userSortIndicator('status', sortBy, sortDir)}</span>
                                </button>
                            </th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                <button id="users-sort-last-login" type="button" class="flex items-center gap-1 hover:text-gray-700">
                                    Last Login <span class="text-[10px]">${userSortIndicator('last_login_at', sortBy, sortDir)}</span>
                                </button>
                            </th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">${rows}</tbody>
                </table>
            </div>
            <div class="px-6 py-3 border-t border-gray-200 flex items-center justify-between">
                <p class="text-xs text-gray-500">Page ${safePage} of ${totalPages}</p>
                <div class="flex items-center gap-2">
                    <button id="users-page-prev" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${safePage <= 1 ? 'text-gray-400 bg-gray-100 cursor-not-allowed' : 'text-gray-700 hover:bg-gray-50'}" ${safePage <= 1 ? 'disabled aria-disabled="true"' : ''}>Previous</button>
                    <button id="users-page-next" type="button" class="px-3 py-1.5 border border-gray-300 rounded text-xs ${!dashboard.userState.hasMore ? 'text-gray-400 bg-gray-100 cursor-not-allowed' : 'text-gray-700 hover:bg-gray-50'}" ${!dashboard.userState.hasMore ? 'disabled aria-disabled="true"' : ''}>Next</button>
                </div>
            </div>
        </div>
    `;
    dashboard.bindUsersTabControls();
}

export function sortUsersRows(_dashboard, users, sortBy, sortDir) {
    const rows = Array.isArray(users) ? [...users] : [];
    const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
    rows.sort((left, right) => {
        let comparison = 0;
        switch (sortBy) {
            case 'role':
                comparison = collator.compare(
                    String(left?.role || '').toLowerCase(),
                    String(right?.role || '').toLowerCase()
                );
                break;
            case 'status':
                comparison = collator.compare(
                    String(left?.status || '').toLowerCase(),
                    String(right?.status || '').toLowerCase()
                );
                break;
            case 'last_login_at':
                comparison = getUserSortTime(left?.last_login_at) - getUserSortTime(right?.last_login_at);
                break;
            case 'created_at':
                comparison = getUserSortTime(left?.created_at) - getUserSortTime(right?.created_at);
                break;
            case 'updated_at':
                comparison = getUserSortTime(left?.updated_at) - getUserSortTime(right?.updated_at);
                break;
            case 'user':
            default:
                comparison = collator.compare(
                    getUserSortText(left),
                    getUserSortText(right)
                );
                break;
        }
        if (comparison === 0) {
            comparison = collator.compare(String(left?.id || ''), String(right?.id || ''));
        }
        return sortDir === 'asc' ? comparison : -comparison;
    });
    return rows;
}

export function getUserSortText(user) {
    return String(user?.email || user?.display_name || user?.id || '').toLowerCase();
}

export function getUserSortTime(value) {
    const parsed = Date.parse(String(value || ''));
    return Number.isNaN(parsed) ? 0 : parsed;
}

export function userSortIndicator(key, activeBy, activeDir) {
    if (String(key) !== String(activeBy)) {
        return '↕';
    }
    return String(activeDir) === 'asc' ? '▲' : '▼';
}

export function userSortDescriptor(sortBy, sortDir) {
    const labels = {
        user: 'user',
        role: 'role',
        status: 'status',
        last_login_at: 'last login',
        created_at: 'created',
        updated_at: 'updated'
    };
    const base = labels[String(sortBy || '').toLowerCase()] || 'updated';
    return `${base} ${String(sortDir) === 'asc' ? 'asc' : 'desc'}`;
}
