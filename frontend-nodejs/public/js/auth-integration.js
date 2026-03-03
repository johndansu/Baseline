/**
 * Enhanced Authentication Integration for Node.js Backend
 * Works with existing auth.js to provide server-side validation
 */

(function() {
  'use strict';

  // Enhanced auth state with server integration
  const enhancedAuthState = {
    serverSession: null,
    tokenRefreshInProgress: false,
    lastActivity: Date.now()
  };

  /**
   * Make authenticated API requests
   */
  async function makeAuthenticatedRequest(url, options = {}) {
    const session = getCurrentSession();
    
    if (!session || !session.access_token) {
      throw new Error('No valid session available');
    }

    const defaultOptions = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${session.access_token}`
      }
    };

    const response = await fetch(url, {
      ...defaultOptions,
      ...options
    });

    // Handle token expiration
    if (response.status === 401) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry request with new token
        return makeAuthenticatedRequest(url, options);
      }
    }

    return response;
  }

  /**
   * Refresh access token using server endpoint
   */
  async function refreshAccessToken() {
    if (enhancedAuthState.tokenRefreshInProgress) {
      return false;
    }

    enhancedAuthState.tokenRefreshInProgress = true;

    try {
      const session = getCurrentSession();
      if (!session.refresh_token) {
        return false;
      }

      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refreshToken: session.refresh_token
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          // Update local session
          localStorage.setItem('supabase.auth.token', JSON.stringify(data.session));
          updateAuthState();
          return true;
        }
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    } finally {
      enhancedAuthState.tokenRefreshInProgress = false;
    }

    return false;
  }

  /**
   * Check server session validity
   */
  async function checkServerSession() {
    try {
      const session = getCurrentSession();
      if (!session || !session.access_token) {
        return false;
      }

      const response = await fetch('/api/user/profile', {
        headers: {
          'Authorization': `Bearer ${session.access_token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        enhancedAuthState.serverSession = data;
        return data.authenticated;
      }

      return false;
    } catch (error) {
      console.error('Session check failed:', error);
      return false;
    }
  }

  /**
   * Get current session from localStorage
   */
  function getCurrentSession() {
    try {
      const tokenData = localStorage.getItem('supabase.auth.token');
      return tokenData ? JSON.parse(tokenData) : null;
    } catch (error) {
      console.error('Failed to parse session:', error);
      return null;
    }
  }

  /**
   * Update auth state with server validation
   */
  async function updateAuthState() {
    const isValid = await checkServerSession();
    
    // Update UI based on authentication state
    updateAuthUI(isValid);
    
    // Redirect if needed
    handleAuthRedirects(isValid);
  }

  /**
   * Update UI elements based on auth state
   */
  function updateAuthUI(isAuthenticated) {
    // Update navigation buttons
    const authButtons = document.querySelectorAll('.auth-button');
    authButtons.forEach(button => {
      if (isAuthenticated) {
        button.textContent = 'Sign Out';
        button.onclick = handleSignOut;
      } else {
        button.textContent = 'Sign In';
        button.onclick = () => window.location.href = '/signin.html';
      }
    });

    // Update user profile display
    const profileElements = document.querySelectorAll('.user-profile');
    profileElements.forEach(element => {
      if (isAuthenticated && enhancedAuthState.serverSession?.user) {
        element.style.display = 'block';
        const userName = element.querySelector('.user-name');
        if (userName) {
          userName.textContent = enhancedAuthState.serverSession.user.full_name || 
                            enhancedAuthState.serverSession.user.email;
        }
      } else {
        element.style.display = 'none';
      }
    });
  }

  /**
   * Handle redirects based on auth state
   */
  function handleAuthRedirects(isAuthenticated) {
    const currentPath = window.location.pathname;
    
    // Redirect unauthenticated users from protected pages
    if (!isAuthenticated && isProtectedRoute(currentPath)) {
      window.location.href = '/signin.html';
      return;
    }

    // Redirect authenticated users from auth pages
    if (isAuthenticated && isAuthRoute(currentPath)) {
      window.location.href = '/dashboard.html';
      return;
    }
  }

  /**
   * Check if route requires authentication
   */
  function isProtectedRoute(path) {
    const protectedRoutes = ['/dashboard.html', '/dashboard'];
    return protectedRoutes.some(route => path.startsWith(route));
  }

  /**
   * Check if route is for authentication
   */
  function isAuthRoute(path) {
    const authRoutes = ['/signin.html', '/signup.html'];
    return authRoutes.includes(path);
  }

  /**
   * Handle sign out
   */
  async function handleSignOut() {
    try {
      // Call server sign out
      const response = await fetch('/api/auth/signout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        // Clear local storage
        localStorage.removeItem('supabase.auth.token');
        enhancedAuthState.serverSession = null;
        
        // Redirect to home
        window.location.href = '/index.html';
      }
    } catch (error) {
      console.error('Sign out failed:', error);
    }
  }

  /**
   * Initialize enhanced authentication
   */
  async function initializeEnhancedAuth() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initializeEnhancedAuth);
      return;
    }

    // Check authentication state on page load
    await updateAuthState();

    // Set up periodic session validation
    setInterval(async () => {
      const session = getCurrentSession();
      if (session && session.access_token) {
        await updateAuthState();
      }
    }, 5 * 60 * 1000); // Check every 5 minutes

    // Update activity timestamp on user interaction
    document.addEventListener('click', () => {
      enhancedAuthState.lastActivity = Date.now();
    });
  }

  // Expose functions globally
  window.enhancedAuth = {
    makeAuthenticatedRequest,
    refreshAccessToken,
    checkServerSession,
    updateAuthState,
    handleSignOut,
    getCurrentSession
  };

  // Initialize on page load
  initializeEnhancedAuth();

})();
