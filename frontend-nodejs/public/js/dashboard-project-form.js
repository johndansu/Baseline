export function bindAddProjectForm(dashboard) {
    const form = document.getElementById('add-project-form');
    if (!form || form.dataset.bound === '1') {
        return;
    }
    form.dataset.bound = '1';
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitAddProjectForm(dashboard);
    });
}

export function prepareAddProjectModal(dashboard) {
    if (!dashboard.hasCapability('projects.write')) {
        dashboard.showError('Project write access is required.');
        if (typeof window.closeModal === 'function') {
            window.closeModal('addProjectModal');
        }
        return;
    }
    bindAddProjectForm(dashboard);

    const form = document.getElementById('add-project-form');
    const title = document.getElementById('add-project-modal-title');
    const nameInput = document.getElementById('add-project-name');
    const repoInput = document.getElementById('add-project-repo');
    const branchInput = document.getElementById('add-project-branch');
    const policySetInput = document.getElementById('add-project-policy-set');
    const submitButton = document.getElementById('add-project-submit');

    if (!form || !nameInput || !repoInput || !branchInput || !policySetInput) {
        return;
    }

    const pendingID = String(dashboard.pendingProjectEditID || '').trim();
    const project = pendingID ? dashboard.projectState.byID.get(pendingID) : null;
    dashboard.pendingProjectEditID = '';

    if (project) {
        form.dataset.mode = 'edit';
        form.dataset.projectId = project.id;
        if (title) title.textContent = 'Edit Project';
        nameInput.value = project.name || '';
        repoInput.value = project.repository_url || '';
        branchInput.value = project.default_branch || 'main';
        policySetInput.value = project.policy_set || 'baseline:prod';
        setAddProjectFeedback(`Updating project ${project.name || project.id}.`, false);
    } else {
        form.dataset.mode = 'create';
        delete form.dataset.projectId;
        if (title) title.textContent = 'Add New Project';
        nameInput.value = '';
        repoInput.value = '';
        branchInput.value = 'main';
        policySetInput.value = 'baseline:prod';
        setAddProjectFeedback('Creates a new project and refreshes dashboard data.', false);
    }
    if (submitButton) submitButton.disabled = false;
}

export function setAddProjectFeedback(message, isError) {
    const feedback = document.getElementById('add-project-feedback');
    if (!feedback) {
        return;
    }
    feedback.textContent = message;
    feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
}

export async function submitAddProjectForm(dashboard) {
    if (!dashboard.hasCapability('projects.write')) {
        dashboard.showError('Project write access is required.');
        return;
    }
    const form = document.getElementById('add-project-form');
    const nameInput = document.getElementById('add-project-name');
    const repoInput = document.getElementById('add-project-repo');
    const branchInput = document.getElementById('add-project-branch');
    const policySetInput = document.getElementById('add-project-policy-set');
    const submitButton = document.getElementById('add-project-submit');

    if (!form || !nameInput || !repoInput || !branchInput || !policySetInput) {
        dashboard.showError('Add Project form is not available.');
        return;
    }

    const name = String(nameInput.value || '').trim();
    const repositoryURL = String(repoInput.value || '').trim();
    const defaultBranch = String(branchInput.value || '').trim() || 'main';
    const policySet = String(policySetInput.value || '').trim() || 'baseline:prod';

    if (!name) {
        setAddProjectFeedback('Project name is required.', true);
        return;
    }
    if (/\s/.test(defaultBranch)) {
        setAddProjectFeedback('Default branch cannot contain whitespace.', true);
        return;
    }
    if (/\s/.test(policySet)) {
        setAddProjectFeedback('Policy set cannot contain whitespace.', true);
        return;
    }

    const payload = {
        name: name,
        repository_url: repositoryURL,
        default_branch: defaultBranch,
        policy_set: policySet
    };
    const isEdit = String(form.dataset.mode || 'create') === 'edit';
    const projectID = String(form.dataset.projectId || '').trim();
    if (isEdit && !projectID) {
        setAddProjectFeedback('Missing project identifier for update.', true);
        return;
    }
    const method = isEdit ? 'PUT' : 'POST';
    const path = isEdit ? `/v1/projects/${encodeURIComponent(projectID)}` : '/v1/projects';

    if (submitButton) submitButton.disabled = true;
    setAddProjectFeedback(isEdit ? 'Submitting project update...' : 'Submitting project creation...', false);

    try {
        const created = await dashboard.apiRequest(path, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (typeof window.closeModal === 'function') {
            window.closeModal('addProjectModal');
        }
        await Promise.allSettled([
            dashboard.loadDashboardData(),
            dashboard.loadProjectsData()
        ]);
        const createdName = created && created.name ? ` ${created.name}` : '';
        dashboard.showSuccess(isEdit
            ? `Project${createdName} updated successfully.`
            : `Project${createdName} created successfully.`);
    } catch (error) {
        setAddProjectFeedback(error.message || (isEdit ? 'Failed to update project.' : 'Failed to create project.'), true);
        dashboard.showError(error.message || (isEdit ? 'Failed to update project.' : 'Failed to create project.'));
    } finally {
        if (submitButton) submitButton.disabled = false;
    }
}

export function openEditProjectModal(dashboard, projectID) {
    if (!dashboard.hasCapability('projects.write')) {
        dashboard.showError('Project write access is required.');
        return;
    }
    const normalizedID = String(projectID || '').trim();
    if (!normalizedID) {
        dashboard.showError('Invalid project selected.');
        return;
    }
    if (!dashboard.projectState.byID.has(normalizedID)) {
        dashboard.showError('Project details not loaded yet.');
        return;
    }
    dashboard.pendingProjectEditID = normalizedID;
    if (typeof window.openModal === 'function') {
        window.openModal('addProjectModal');
    }
}
