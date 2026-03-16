export function bindSettingsControls(dashboard) {
    const cliApproveButton = document.getElementById('settings-cli-approve-button');
    if (cliApproveButton && cliApproveButton.dataset.bound !== '1') {
        cliApproveButton.dataset.bound = '1';
        cliApproveButton.addEventListener('click', () => {
            dashboard.openCLILoginApprovalModal();
        });
    }

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

    document.querySelectorAll('[data-cli-session-revoke]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async () => {
            const sessionID = String(button.dataset.cliSessionRevoke || '').trim();
            if (!sessionID) {
                return;
            }
            button.disabled = true;
            try {
                await dashboard.revokeCLISession(sessionID);
            } finally {
                button.disabled = false;
            }
        });
    });

    document.querySelectorAll('[data-cli-session-view]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async () => {
            const sessionID = String(button.dataset.cliSessionView || '').trim();
            if (!sessionID) {
                return;
            }
            await dashboard.openCLISessionDetail(sessionID);
        });
    });

    document.querySelectorAll('[data-cli-session-revoke-user]').forEach((button) => {
        if (button.dataset.bound === '1') {
            return;
        }
        button.dataset.bound = '1';
        button.addEventListener('click', async () => {
            const userID = String(button.dataset.cliSessionRevokeUser || '').trim();
            const userLabel = String(button.dataset.cliSessionUserLabel || '').trim();
            if (!userID) {
                return;
            }
            button.disabled = true;
            try {
                await dashboard.revokeCLISessionsForUser(userID, userLabel);
            } finally {
                button.disabled = false;
            }
        });
    });

    const cliApprovalSubmitButton = document.getElementById('cli-login-approval-submit');
    if (cliApprovalSubmitButton && cliApprovalSubmitButton.dataset.bound !== '1') {
        cliApprovalSubmitButton.dataset.bound = '1';
        cliApprovalSubmitButton.addEventListener('click', async () => {
            await dashboard.submitCLILoginApproval();
        });
    }

    const cliApprovalInput = document.getElementById('cli-login-user-code');
    if (cliApprovalInput && cliApprovalInput.dataset.bound !== '1') {
        cliApprovalInput.dataset.bound = '1';
        cliApprovalInput.addEventListener('input', () => {
            dashboard.syncCLILoginApprovalCode();
        });
    }
}
