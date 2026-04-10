export function adminUserRowKey(userID) {
    return String(userID || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

export async function submitAdminUserCreate(dashboard) {
    const emailField = document.getElementById('admin-user-create-email');
    const nameField = document.getElementById('admin-user-create-display-name');
    const roleField = document.getElementById('admin-user-create-role');
    const statusField = document.getElementById('admin-user-create-status');
    const feedback = document.getElementById('admin-users-feedback');
    const email = String(emailField?.value || '').trim().toLowerCase();
    const displayName = String(nameField?.value || '').trim();
    const role = String(roleField?.value || 'viewer').trim().toLowerCase();
    const status = String(statusField?.value || 'active').trim().toLowerCase();

    if (!email) {
        dashboard.showError('Email is required.');
        if (feedback) {
            feedback.textContent = 'Email is required to create a user.';
            feedback.className = 'mt-2 text-xs text-red-600';
        }
        return;
    }

    if (feedback) {
        feedback.textContent = `Creating ${email}...`;
        feedback.className = 'mt-2 text-xs text-gray-500';
    }
    try {
        const createdUser = await dashboard.apiRequest('/v1/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, display_name: displayName, role, status })
        });
        if (emailField) emailField.value = '';
        if (nameField) nameField.value = '';
        if (roleField) roleField.value = 'viewer';
        if (statusField) statusField.value = 'active';
        await dashboard.loadUsersData(true);
        if (createdUser && typeof createdUser === 'object' && createdUser.id) {
            dashboard.userState.selected = createdUser;
        }
        if (dashboard.currentTab === 'users') {
            await dashboard.loadUsersTabData();
        }
        const refreshedFeedback = document.getElementById('admin-users-feedback');
        if (refreshedFeedback) {
            refreshedFeedback.textContent = `Created ${email} successfully.`;
            refreshedFeedback.className = 'mt-2 text-xs text-green-700';
        }
        dashboard.showSuccess(`Created ${email}.`);
    } catch (error) {
        if (feedback) {
            feedback.textContent = error.message || `Failed to create ${email}.`;
            feedback.className = 'mt-2 text-xs text-red-600';
        }
        dashboard.showError(error.message || `Failed to create ${email}.`);
    }
}

export async function setSelectedUserStatus(dashboard, userID, status) {
    const id = String(userID || '').trim();
    const nextStatus = String(status || '').trim().toLowerCase();
    const detailStatusField = document.getElementById('admin-user-detail-status');
    if (detailStatusField && (nextStatus === 'active' || nextStatus === 'suspended')) {
        detailStatusField.value = nextStatus;
    }
    await submitAdminUserUpdate(dashboard, id, 'detail');
}

export async function submitAdminUserUpdate(dashboard, userID, source = 'row') {
    const id = String(userID || '').trim();
    if (!id) {
        dashboard.showError('Invalid user id.');
        return;
    }
    const rowKey = adminUserRowKey(id);
    const roleField = source === 'detail'
        ? document.getElementById('admin-user-detail-role')
        : document.getElementById(`admin-user-role-${rowKey}`);
    const statusField = source === 'detail'
        ? document.getElementById('admin-user-detail-status')
        : document.getElementById(`admin-user-status-${rowKey}`);
    const feedback = document.getElementById('admin-users-feedback');
    if (!roleField || !statusField) {
        dashboard.showError('User controls are not available.');
        return;
    }
    const role = String(roleField.value || '').trim().toLowerCase();
    const status = String(statusField.value || '').trim().toLowerCase();
    if (feedback) {
        feedback.textContent = `Updating ${id}...`;
        feedback.className = 'mt-2 text-xs text-gray-500';
    }
    try {
        const updatedUser = await dashboard.apiRequest(`/v1/users/${encodeURIComponent(id)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role, status })
        });
        if (updatedUser && typeof updatedUser === 'object') {
            dashboard.userState.byID.set(id, updatedUser);
            if (dashboard.userState.selected && String(dashboard.userState.selected.id || '').trim() === id) {
                dashboard.userState.selected = updatedUser;
            }
        }
        await dashboard.loadUsersData(true);
        if (dashboard.currentTab === 'users') {
            await dashboard.loadUsersTabData();
        }
        const refreshedFeedback = document.getElementById('admin-users-feedback');
        if (refreshedFeedback) {
            refreshedFeedback.textContent = `Updated ${id} successfully.`;
            refreshedFeedback.className = 'mt-2 text-xs text-green-700';
        }
        dashboard.showSuccess(`Updated ${id}.`);
        if (dashboard.currentTab === 'keys') {
            await dashboard.loadApiKeysData();
        }
    } catch (error) {
        if (feedback) {
            feedback.textContent = error.message || `Failed to update ${id}.`;
            feedback.className = 'mt-2 text-xs text-red-600';
        }
        dashboard.showError(error.message || `Failed to update ${id}.`);
    }
}
