export function renderProjectsTable(dashboard, projects) {
    const projectsTab = document.getElementById('projects-tab');
    if (!projectsTab) return;
    const canWriteProjects = dashboard.hasCapability('projects.write');
    const isAdmin = dashboard.isAdmin();
    const showActions = true;
    const editActionHeader = showActions
        ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>`
        : '';
    const ownerHeader = `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>`;
    const helperCopy = isAdmin
        ? 'Projects appear here after Baseline connects a repository or uploads a scan. Owner assignment is admin-only.'
        : 'Projects appear here after Baseline connects a repository or uploads a scan. If one is missing, reconnect that repo from the CLI.';

    if (!Array.isArray(projects) || projects.length === 0) {
        projectsTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                    <p class="text-sm text-gray-700 mt-1">No projects found yet.</p>
                    <p class="text-sm text-gray-500 mt-2">${helperCopy}</p>
                </div>
            </div>
        `;
        return;
    }

    projectsTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200">
            <div class="p-6 border-b border-gray-200">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                    <p class="text-sm text-gray-700 mt-1">Projects Baseline already knows about, plus their latest scan posture.</p>
                    <p class="text-sm text-gray-500 mt-2">${helperCopy}</p>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Repository</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Branch</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Policy Set</th>
                            ${ownerHeader}
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scans</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            ${editActionHeader}
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${projects.map(project => `
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${dashboard.escapeHtml(project.name)}</td>
                                <td class="px-6 py-4 text-sm text-gray-700">${dashboard.escapeHtml(project.repository_url || '-')}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(project.default_branch)}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(project.policy_set)}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${dashboard.escapeHtml(dashboard.describeProjectOwner(project.owner_id))}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${project.scan_count}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${dashboard.formatDate(project.last_scan_at)}</td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="px-2 py-1 text-xs rounded-full ${dashboard.statusBadgeClass(project.last_scan_status)}">${dashboard.escapeHtml(project.last_scan_status.toUpperCase())}</span>
                                </td>
                                ${showActions ? `
                                    <td class="px-6 py-4 whitespace-nowrap text-sm">
                                        <div class="flex items-center gap-3">
                                            ${canWriteProjects ? `
                                                <button
                                                    type="button"
                                                    data-project-action="edit"
                                                    data-project-id="${dashboard.escapeHtml(project.id)}"
                                                    class="text-orange-600 hover:text-orange-700 font-medium"
                                                >
                                                    Edit
                                                </button>
                                            ` : ''}
                                            <button
                                                type="button"
                                                data-project-action="view"
                                                data-project-id="${dashboard.escapeHtml(project.id)}"
                                                class="text-gray-700 hover:text-gray-900 font-medium"
                                            >
                                                View
                                            </button>
                                            ${isAdmin ? `
                                                <button
                                                    type="button"
                                                    data-project-action="assign-owner"
                                                    data-project-id="${dashboard.escapeHtml(project.id)}"
                                                    class="text-gray-600 hover:text-gray-900 font-medium"
                                                >
                                                    Assign owner
                                                </button>
                                            ` : ''}
                                        </div>
                                    </td>
                                ` : ''}
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    dashboard.bindModalTriggerButtons(projectsTab);
    dashboard.bindProjectActionButtons(projectsTab);
}
