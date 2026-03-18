export function openModal(modalID) {
    const modal = document.getElementById(String(modalID || '').trim());
    if (!modal) {
        return;
    }
    modal.classList.remove('hidden');
    modal.classList.add('flex');
    document.body.classList.add('overflow-hidden');
}

function prepareDashboardModal(modalID) {
    if (typeof window === 'undefined') {
        return;
    }
    const dashboard = window.baselineDashboard;
    if (!dashboard) {
        return;
    }
    const modalPreparers = {
        addProjectModal: 'prepareAddProjectModal',
        generateKeyModal: 'prepareGenerateKeyModal',
        revokeKeyModal: 'prepareRevokeKeyModal',
        runScanModal: 'prepareRunScanModal',
        projectOwnerModal: 'prepareProjectOwnerModal'
    };
    const methodName = modalPreparers[String(modalID || '').trim()];
    if (!methodName || typeof dashboard[methodName] !== 'function') {
        return;
    }
    return dashboard[methodName]();
}

export function closeModal(modalID) {
    const modal = document.getElementById(String(modalID || '').trim());
    if (!modal) {
        return;
    }
    modal.classList.add('hidden');
    modal.classList.remove('flex');
    if (!document.querySelector('.fixed.inset-0.z-50:not(.hidden)')) {
        document.body.classList.remove('overflow-hidden');
    }
}

if (typeof window !== 'undefined') {
    window.openModal = openModal;
    window.closeModal = closeModal;
}

export function bindModalTriggerButtons(root = document) {
    root.querySelectorAll('[data-open-modal]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async (event) => {
            event.preventDefault();
            const modalID = String(button.dataset.openModal || '').trim();
            if (!modalID) {
                return;
            }
            openModal(modalID);
            try {
                await prepareDashboardModal(modalID);
            } catch (error) {
                if (typeof window !== 'undefined' && window.baselineDashboard?.showError) {
                    window.baselineDashboard.showError(error?.message || 'Failed to prepare modal.');
                }
            }
        });
    });

    root.querySelectorAll('[data-close-modal]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', (event) => {
            event.preventDefault();
            const modalID = String(button.dataset.closeModal || '').trim();
            if (!modalID) {
                return;
            }
            closeModal(modalID);
        });
    });

    root.querySelectorAll('.fixed.inset-0.z-50').forEach((modal) => {
        if (modal.dataset.backdropBound === '1') {
            return;
        }
        modal.dataset.backdropBound = '1';
        modal.addEventListener('click', (event) => {
            if (event.target !== modal) {
                return;
            }
            if (!modal.id) {
                return;
            }
            closeModal(modal.id);
        });
    });
}
