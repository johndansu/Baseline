export function openModal(modalID) {
    const modal = document.getElementById(String(modalID || '').trim());
    if (!modal) {
        return;
    }
    modal.classList.remove('hidden');
    modal.classList.add('flex');
    document.body.classList.add('overflow-hidden');
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
        button.addEventListener('click', (event) => {
            event.preventDefault();
            const modalID = String(button.dataset.openModal || '').trim();
            if (!modalID) {
                return;
            }
            openModal(modalID);
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
