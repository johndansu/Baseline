export function bindSettingsControls(dashboard) {
    const profileSaveButton = document.getElementById('settings-profile-save');
    if (profileSaveButton && profileSaveButton.dataset.bound !== '1') {
        profileSaveButton.dataset.bound = '1';
        profileSaveButton.addEventListener('click', async () => {
            await dashboard.saveProfileSettings();
        });
    }

    const preferenceSaveButton = document.getElementById('settings-preferences-save');
    if (preferenceSaveButton && preferenceSaveButton.dataset.bound !== '1') {
        preferenceSaveButton.dataset.bound = '1';
        preferenceSaveButton.addEventListener('click', async () => {
            dashboard.saveDashboardPreferencesFromSettings();
        });
    }

    const preferenceResetButton = document.getElementById('settings-preferences-reset');
    if (preferenceResetButton && preferenceResetButton.dataset.bound !== '1') {
        preferenceResetButton.dataset.bound = '1';
        preferenceResetButton.addEventListener('click', () => {
            dashboard.resetDashboardPreferencesFromSettings();
        });
    }

    const passwordSaveButton = document.getElementById('settings-password-save');
    if (passwordSaveButton && passwordSaveButton.dataset.bound !== '1') {
        passwordSaveButton.dataset.bound = '1';
        passwordSaveButton.addEventListener('click', async () => {
            await dashboard.savePasswordSettings();
        });
    }

    document.querySelectorAll('[data-settings-nav]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            const targetTab = String(button.dataset.settingsNav || '').trim();
            if (targetTab) {
                dashboard.switchTab(targetTab);
            }
        });
    });

    document.querySelectorAll('[data-settings-url]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', () => {
            const url = String(button.dataset.settingsUrl || '').trim();
            if (url) {
                window.open(url, '_blank', 'noopener,noreferrer');
            }
        });
    });
}
