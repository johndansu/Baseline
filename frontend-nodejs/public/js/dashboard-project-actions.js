export function bindProjectActionButtons(dashboard, root = document) {
    root.querySelectorAll('[data-project-action]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async (event) => {
            event.preventDefault();
            const projectID = String(button.dataset.projectId || '').trim();
            const action = String(button.dataset.projectAction || '').trim();
            if (!projectID || !action) {
                return;
            }
            if (action === 'edit') {
                dashboard.openEditProjectModal(projectID);
                return;
            }
            if (action === 'view') {
                await dashboard.openProjectDetailsModal(projectID);
                return;
            }
            if (action === 'assign-owner') {
                dashboard.openProjectOwnerModal(projectID);
            }
        });
    });
}
