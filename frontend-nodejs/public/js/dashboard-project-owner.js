export function bindProjectOwnerForm(dashboard) {
    const form = document.getElementById('project-owner-form');
    if (!form || form.dataset.bound === '1') {
        return;
    }
    form.dataset.bound = '1';
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitProjectOwnerForm(dashboard);
    });
}

export async function prepareProjectOwnerModal(dashboard) {
    if (!dashboard.isAdmin()) {
        dashboard.showError('Admin access is required.');
        if (typeof window.closeModal === 'function') {
            window.closeModal('projectOwnerModal');
        }
        return;
    }
    bindProjectOwnerForm(dashboard);
    const projectID = String(dashboard.pendingProjectOwnerID || '').trim();
    if (!projectID) {
        dashboard.showError('Project owner assignment is missing a project.');
        if (typeof window.closeModal === 'function') {
            window.closeModal('projectOwnerModal');
        }
        return;
    }

    await dashboard.loadUsersData();
    const project = dashboard.projectState.byID.get(projectID);
    if (!project) {
        dashboard.showError('Project details are not available.');
        if (typeof window.closeModal === 'function') {
            window.closeModal('projectOwnerModal');
        }
        return;
    }

    const title = document.getElementById('project-owner-modal-title');
    const projectLabel = document.getElementById('project-owner-project-label');
    const currentOwner = document.getElementById('project-owner-current-owner');
    const select = document.getElementById('project-owner-user-select');
    const submitButton = document.getElementById('project-owner-submit');

    if (title) title.textContent = 'Assign Project Owner';
    if (projectLabel) projectLabel.textContent = project.name || project.id || 'Project';
    if (currentOwner) currentOwner.textContent = describeProjectOwner(dashboard, project.owner_id);
    if (select) {
        const options = dashboard.userState.all
            .filter((user) => String(user?.id || '').trim())
            .sort((a, b) => String(a.email || a.display_name || a.id || '').localeCompare(String(b.email || b.display_name || b.id || '')))
            .map((user) => {
                const userID = String(user.id || '').trim();
                const selected = String(project.owner_id || '').toLowerCase() === `user:${userID.toLowerCase()}` ? ' selected' : '';
                const label = user.email || user.display_name || userID;
                return `<option value="${dashboard.escapeHtml(userID)}"${selected}>${dashboard.escapeHtml(label)}</option>`;
            });
        const currentOwnerID = currentPrincipalOwnerID(dashboard);
        if (currentOwnerID.startsWith('user:')) {
            const currentUserID = currentOwnerID.slice('user:'.length);
            const exists = dashboard.userState.all.some((user) => String(user?.id || '').trim().toLowerCase() === currentUserID.toLowerCase());
            if (!exists) {
                const selected = String(project.owner_id || '').toLowerCase() === currentOwnerID.toLowerCase() ? ' selected' : '';
                options.unshift(`<option value="${dashboard.escapeHtml(currentUserID)}"${selected}>You (${dashboard.escapeHtml(dashboard.identity.email || dashboard.identity.user || currentUserID)})</option>`);
            }
        }
        select.innerHTML = `<option value="">Select a user</option>${options.join('')}`;
    }
    if (submitButton) submitButton.disabled = false;
    setProjectOwnerFeedback('Choose the user who should own new scans for this project.', false);
}

export function setProjectOwnerFeedback(message, isError) {
    const feedback = document.getElementById('project-owner-feedback');
    if (!feedback) {
        return;
    }
    feedback.textContent = message;
    feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
}

export async function submitProjectOwnerForm(dashboard) {
    if (!dashboard.isAdmin()) {
        dashboard.showError('Admin access is required.');
        return;
    }
    const projectID = String(dashboard.pendingProjectOwnerID || '').trim();
    const select = document.getElementById('project-owner-user-select');
    const submitButton = document.getElementById('project-owner-submit');
    if (!projectID || !select) {
        dashboard.showError('Project owner form is not available.');
        return;
    }
    const userID = String(select.value || '').trim();
    if (!userID) {
        setProjectOwnerFeedback('Select a user to continue.', true);
        return;
    }

    if (submitButton) submitButton.disabled = true;
    setProjectOwnerFeedback('Assigning project owner...', false);
    try {
        const updated = await dashboard.apiRequest(`/v1/projects/${encodeURIComponent(projectID)}/owner`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_id: userID })
        });
        if (typeof window.closeModal === 'function') {
            window.closeModal('projectOwnerModal');
        }
        dashboard.pendingProjectOwnerID = '';
        await Promise.allSettled([
            dashboard.loadDashboardData(),
            dashboard.loadProjectsData()
        ]);
        dashboard.showSuccess(`Project owner updated to ${describeProjectOwner(dashboard, updated?.owner_id || '')}.`);
    } catch (error) {
        setProjectOwnerFeedback(error.message || 'Failed to assign project owner.', true);
        dashboard.showError(error.message || 'Failed to assign project owner.');
    } finally {
        if (submitButton) submitButton.disabled = false;
    }
}

export async function claimProject(dashboard, projectID) {
    const normalizedID = String(projectID || '').trim();
    if (!normalizedID) {
        dashboard.showError('Invalid project selected.');
        return;
    }
    try {
        const updated = await dashboard.apiRequest(`/v1/projects/${encodeURIComponent(normalizedID)}/claim`, {
            method: 'POST'
        });
        await Promise.allSettled([
            dashboard.loadDashboardData(),
            dashboard.loadProjectsData()
        ]);
        dashboard.showSuccess(`Project now belongs to ${describeProjectOwner(dashboard, updated?.owner_id || currentPrincipalOwnerID(dashboard))}.`);
    } catch (error) {
        dashboard.showError(error.message || 'Failed to claim project.');
    }
}

export async function openProjectOwnerModal(dashboard, projectID) {
    if (!dashboard.isAdmin()) {
        dashboard.showError('Admin access is required.');
        return;
    }
    const normalizedID = String(projectID || '').trim();
    if (!normalizedID) {
        dashboard.showError('Invalid project selected.');
        return;
    }
    dashboard.pendingProjectOwnerID = normalizedID;
    if (typeof window.openModal === 'function') {
        window.openModal('projectOwnerModal');
    }
    await prepareProjectOwnerModal(dashboard);
}

export function currentPrincipalOwnerID(dashboard) {
    if (dashboard.identity.userID) {
        return `user:${String(dashboard.identity.userID).trim().toLowerCase()}`;
    }
    if (dashboard.identity.subject) {
        return `sub:${String(dashboard.identity.subject).trim().toLowerCase()}`;
    }
    if (dashboard.identity.email) {
        return `email:${String(dashboard.identity.email).trim().toLowerCase()}`;
    }
    if (dashboard.identity.user) {
        return `user:${String(dashboard.identity.user).trim().toLowerCase()}`;
    }
    return '';
}

export function describeProjectOwner(dashboard, ownerID) {
    const normalized = String(ownerID || '').trim();
    if (!normalized) {
        return 'Unassigned';
    }
    if (normalized.toLowerCase() === currentPrincipalOwnerID(dashboard)) {
        return 'You';
    }
    if (normalized.startsWith('user:')) {
        const userID = normalized.slice('user:'.length);
        const user = dashboard.userState.byID.get(userID) || dashboard.userState.byID.get(userID.toLowerCase()) || null;
        if (user) {
            return user.email || user.display_name || user.id || normalized;
        }
        return `User ${userID}`;
    }
    if (normalized.startsWith('email:')) {
        return normalized.slice('email:'.length);
    }
    if (normalized.startsWith('sub:')) {
        return 'Linked identity';
    }
    if (normalized.startsWith('api_key:')) {
        return `API key ${normalized.slice('api_key:'.length)}`;
    }
    return normalized;
}
