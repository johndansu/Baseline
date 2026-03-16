export function bindAPIKeyActionButtons(dashboard, root = document) {
    root.querySelectorAll('[data-key-action]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', (event) => {
            event.preventDefault();
            const keyID = String(button.dataset.keyId || '').trim();
            const action = String(button.dataset.keyAction || '').trim();
            if (!keyID || !action) {
                return;
            }
            if (action === 'revoke') {
                dashboard.openRevokeKeyModal(keyID);
            }
        });
    });
}
