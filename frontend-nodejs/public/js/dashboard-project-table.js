export function renderProjectsTable(dashboard, projects) {
    const projectsTab = document.getElementById('projects-tab');
    if (!projectsTab) return;
    const canWriteProjects = dashboard.hasCapability('projects.write');
    const isAdmin = dashboard.isAdmin();
    const showActions = true;
    const addProjectButton = canWriteProjects
        ? `<button type="button" data-open-modal="addProjectModal" class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm font-medium">Add Project</button>`
        : `<button type="button" class="px-4 py-2 border border-gray-300 text-gray-400 bg-gray-100 rounded-lg text-sm font-medium cursor-not-allowed" aria-disabled="true" disabled>Add Project</button>`;
    const editActionHeader = showActions
        ? `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>`
        : '';
    const ownerHeader = `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>`;

    if (!Array.isArray(projects) || projects.length === 0) {
        projectsTab.innerHTML = `
            <div class="bg-white rounded-lg border border-gray-200 p-6">
                <div class="flex items-center justify-between gap-4">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                        <p class="text-sm text-gray-700 mt-1">No projects found.</p>
                    </div>
                    ${addProjectButton}
                </div>
            </div>
        `;
        return;
    }

    projectsTab.innerHTML = `
        <div class="bg-white rounded-lg border border-gray-200">
            <div class="p-6 border-b border-gray-200 flex items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-semibold text-gray-900">Projects</h3>
                    <p class="text-sm text-gray-700 mt-1">Live projects and scan posture from backend APIs</p>
                </div>
                ${addProjectButton}
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
