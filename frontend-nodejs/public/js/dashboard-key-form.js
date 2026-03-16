export function bindGenerateKeyForm(dashboard) {
    const form = document.getElementById('generate-key-form');
    if (!form || form.dataset.bound === '1') {
        return;
    }
    form.dataset.bound = '1';
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitGenerateKeyForm(dashboard);
    });

    const copyButton = document.getElementById('issued-key-copy-btn');
    if (copyButton && copyButton.dataset.bound !== '1') {
        copyButton.dataset.bound = '1';
        copyButton.addEventListener('click', async () => {
            await copyIssuedAPIKey(dashboard);
        });
    }
}

export function prepareGenerateKeyModal(dashboard) {
    if (!dashboard.hasCapability('api_keys.write')) {
        dashboard.showError('API key write access is required.');
        if (typeof window.closeModal === 'function') {
            window.closeModal('generateKeyModal');
        }
        return;
    }
    bindGenerateKeyForm(dashboard);
    const nameInput = document.getElementById('generate-key-name');
    const roleSelect = document.getElementById('generate-key-role');
    const submitButton = document.getElementById('generate-key-submit');
    if (!nameInput || !roleSelect) {
        return;
    }
    nameInput.value = '';
    const roleOptions = dashboard.allowedRoleOptionsForCurrentScope();
    roleSelect.innerHTML = roleOptions
        .map(role => `<option value="${dashboard.escapeHtml(role)}">${dashboard.escapeHtml(role.charAt(0).toUpperCase() + role.slice(1))}</option>`)
        .join('');
    roleSelect.value = roleOptions[0] || 'viewer';
    if (submitButton) {
        submitButton.disabled = false;
    }
    const scope = dashboard.resolveAPIKeyScope();
    const scopeLabel = scope.mode === 'user'
        ? `selected user (${dashboard.apiKeyScopeUserLabel()})`
        : scope.mode === 'me'
            ? 'your account'
            : 'admin inventory';
    setGenerateKeyFeedback(`Generated key value is shown once. Scope: ${scopeLabel}.`, false);
}

export function setGenerateKeyFeedback(message, isError) {
    const feedback = document.getElementById('generate-key-feedback');
    if (!feedback) {
        return;
    }
    feedback.textContent = message;
    feedback.className = isError ? 'text-xs text-red-600' : 'text-xs text-gray-500';
}

export async function submitGenerateKeyForm(dashboard) {
    if (!dashboard.hasCapability('api_keys.write')) {
        dashboard.showError('API key write access is required.');
        return;
    }
    const nameInput = document.getElementById('generate-key-name');
    const roleSelect = document.getElementById('generate-key-role');
    const submitButton = document.getElementById('generate-key-submit');
    if (!nameInput || !roleSelect) {
        dashboard.showError('Generate Key form is not available.');
        return;
    }

    const name = String(nameInput.value || '').trim();
    const role = String(roleSelect.value || 'viewer').trim().toLowerCase();
    const allowedRoles = dashboard.allowedRoleOptionsForCurrentScope();
    if (!allowedRoles.includes(role)) {
        setGenerateKeyFeedback('Invalid role selected.', true);
        return;
    }

    const payload = {
        name,
        role
    };

    if (submitButton) {
        submitButton.disabled = true;
    }
    setGenerateKeyFeedback('Issuing API key...', false);

    try {
        const scope = dashboard.resolveAPIKeyScope();
        const created = await dashboard.apiRequest(scope.createPath, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (typeof window.closeModal === 'function') {
            window.closeModal('generateKeyModal');
        }
        await Promise.allSettled([
            dashboard.loadDashboardData(),
            dashboard.loadApiKeysData(),
            dashboard.loadAuditData()
        ]);
        openIssuedKeyModal(dashboard, created);
        dashboard.showSuccess('API key generated successfully.');
    } catch (error) {
        setGenerateKeyFeedback(error.message || 'Failed to generate API key.', true);
        dashboard.showError(error.message || 'Failed to generate API key.');
    } finally {
        if (submitButton) {
            submitButton.disabled = false;
        }
    }
}

export function openIssuedKeyModal(dashboard, created) {
    const keyValue = String(created?.api_key || '').trim();
    dashboard.lastIssuedAPIKey = keyValue;
    dashboard.lastIssuedAPIKeyMeta = created || null;

    const keyField = document.getElementById('issued-key-value');
    const metaField = document.getElementById('issued-key-meta');
    if (keyField) {
        keyField.value = keyValue || 'No key value returned.';
    }
    if (metaField) {
        const id = created?.id ? `id=${created.id}` : '';
        const role = created?.role ? `role=${created.role}` : '';
        const prefix = created?.prefix ? `prefix=${created.prefix}` : '';
        const parts = [id, role, prefix].filter(Boolean);
        metaField.textContent = parts.length ? parts.join(' | ') : '';
    }
    if (typeof window.openModal === 'function') {
        window.openModal('copyKeyModal');
    }
}

export async function copyIssuedAPIKey(dashboard) {
    const keyValue = String(dashboard.lastIssuedAPIKey || '').trim();
    if (!keyValue) {
        dashboard.showError('No issued API key value available to copy.');
        return;
    }
    try {
        await navigator.clipboard.writeText(keyValue);
        dashboard.showSuccess('API key copied to clipboard.');
    } catch (_) {
        dashboard.showError('Unable to copy API key. Copy it manually.');
    }
}
