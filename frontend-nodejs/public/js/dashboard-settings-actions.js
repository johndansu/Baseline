export async function saveProfileSettings(dashboard) {
    const displayNameField = document.getElementById('settings-display-name');
    const feedback = document.getElementById('settings-profile-feedback');
    const saveButton = document.getElementById('settings-profile-save');
    if (!displayNameField || !saveButton) {
        return;
    }

    const displayName = String(displayNameField.value || '').trim();
    if (feedback) {
        feedback.textContent = 'Saving...';
        feedback.className = 'text-xs text-gray-500';
    }
    saveButton.disabled = true;

    try {
        const payload = await dashboard.apiRequest('/v1/auth/me', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ display_name: displayName })
        });
        dashboard.identity.displayName = String(payload?.display_name || displayName).trim();
        if (payload?.email) {
            dashboard.identity.email = String(payload.email).trim().toLowerCase();
        }
        dashboard.updateUserUI({
            displayName: dashboard.identity.displayName,
            email: dashboard.identity.email,
            role: String(payload?.role || dashboard.authz?.role || '')
        });
        if (feedback) {
            feedback.textContent = 'Saved';
            feedback.className = 'text-xs text-green-700';
        }
        dashboard.showSuccess('Profile updated.');
        if (dashboard.currentTab === 'settings') {
            await dashboard.loadSettingsData();
        }
    } catch (error) {
        if (feedback) {
            feedback.textContent = error.message || 'Failed to save profile.';
            feedback.className = 'text-xs text-red-600';
        }
        dashboard.showError(error.message || 'Failed to save profile.');
    } finally {
        saveButton.disabled = false;
    }
}

export function saveDashboardPreferencesFromSettings(dashboard) {
    const defaultTabField = document.getElementById('settings-default-tab');
    const refreshField = document.getElementById('settings-refresh-interval');
    const feedback = document.getElementById('settings-preferences-feedback');
    const nextPreferences = {
        defaultTab: String(defaultTabField?.value || 'overview').trim().toLowerCase(),
        refreshIntervalMs: Number(refreshField?.value || 60000)
    };
    dashboard.persistDashboardPreferences(nextPreferences);
    if (feedback) {
        feedback.textContent = 'Saved';
        feedback.className = 'text-xs text-green-700';
    }
    dashboard.showSuccess('Dashboard preferences updated.');
    dashboard.applyRefreshIntervalPreference();
}

export function resetDashboardPreferencesFromSettings(dashboard) {
    const defaults = { defaultTab: 'overview', refreshIntervalMs: 60000 };
    const defaultTabField = document.getElementById('settings-default-tab');
    const refreshField = document.getElementById('settings-refresh-interval');
    const feedback = document.getElementById('settings-preferences-feedback');
    if (defaultTabField) defaultTabField.value = defaults.defaultTab;
    if (refreshField) refreshField.value = String(defaults.refreshIntervalMs);
    dashboard.persistDashboardPreferences(defaults);
    if (feedback) {
        feedback.textContent = 'Reset to defaults';
        feedback.className = 'text-xs text-green-700';
    }
    dashboard.showSuccess('Dashboard preferences reset.');
    dashboard.applyRefreshIntervalPreference();
}

export async function getSupabaseSettingsClient(dashboard) {
    if (dashboard.supabaseClient) {
        return dashboard.supabaseClient;
    }
    await dashboard.loadExternalScriptOnce('/js/runtime-config.js', 'RUNTIME_CONFIG');
    await dashboard.loadExternalScriptOnce('/js/supabase-config.js', 'getSupabaseConfig');
    await dashboard.loadExternalScriptOnce('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2', 'supabase');
    const config = window.getSupabaseConfig ? window.getSupabaseConfig() : window.SUPABASE_CONFIG;
    if (!config?.url || !config?.anonKey) {
        throw new Error('Supabase runtime config is unavailable.');
    }
    dashboard.supabaseClient = window.supabase.createClient(config.url, config.anonKey, {
        auth: {
            autoRefreshToken: true,
            persistSession: true,
            detectSessionInUrl: false
        }
    });
    return dashboard.supabaseClient;
}

export async function savePasswordSettings(dashboard) {
    const passwordField = document.getElementById('settings-new-password');
    const confirmField = document.getElementById('settings-confirm-password');
    const feedback = document.getElementById('settings-password-feedback');
    const saveButton = document.getElementById('settings-password-save');
    if (!passwordField || !confirmField || !saveButton) {
        return;
    }

    const password = String(passwordField.value || '');
    const confirmPassword = String(confirmField.value || '');
    if (password.length < 8) {
        dashboard.showError('Password must be at least 8 characters.');
        if (feedback) {
            feedback.textContent = 'Password must be at least 8 characters.';
            feedback.className = 'text-xs text-red-600';
        }
        return;
    }
    if (password !== confirmPassword) {
        dashboard.showError('Passwords do not match.');
        if (feedback) {
            feedback.textContent = 'Passwords do not match.';
            feedback.className = 'text-xs text-red-600';
        }
        return;
    }

    saveButton.disabled = true;
    if (feedback) {
        feedback.textContent = 'Saving...';
        feedback.className = 'text-xs text-gray-500';
    }

    try {
        const supabaseClient = await getSupabaseSettingsClient(dashboard);
        const sessionResult = await supabaseClient.auth.getSession();
        if (!sessionResult?.data?.session) {
            throw new Error('Password change requires a fresh sign-in.');
        }
        const result = await supabaseClient.auth.updateUser({ password });
        if (result?.error) {
            throw result.error;
        }
        passwordField.value = '';
        confirmField.value = '';
        if (feedback) {
            feedback.textContent = 'Password updated';
            feedback.className = 'text-xs text-green-700';
        }
        dashboard.showSuccess('Password updated.');
    } catch (error) {
        const message = error?.message || 'Failed to update password.';
        if (feedback) {
            feedback.textContent = message;
            feedback.className = 'text-xs text-red-600';
        }
        dashboard.showError(message);
    } finally {
        saveButton.disabled = false;
    }
}
