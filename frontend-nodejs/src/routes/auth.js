const express = require('express');
const { supabase, getUserSession, refreshAccessToken } = require('../utils/supabase');
const router = express.Router();

const GENERIC_AUTH_FAILURE_MESSAGE = 'Authentication failed. Check your credentials and try again.';
const GENERIC_RESET_MESSAGE = 'If an account exists for this email, a password reset email will be sent.';

/**
 * Sign in user with email and password
 */
router.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Missing credentials',
        message: 'Email and password are required'
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      console.warn('Sign in failed', { code: error.code, status: error.status });
      return res.status(401).json({
        error: 'Authentication failed',
        message: GENERIC_AUTH_FAILURE_MESSAGE
      });
    }

    // Store session for browser access
    if (data.session) {
      req.session.token = data.session.access_token;
      req.session.user = data.session.user;
      req.session.save(() => {});
    }

    res.json({
      success: true,
      user: data.user,
      session: data.session,
      message: 'Sign in successful'
    });
  } catch (error) {
    console.error('Sign in error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred during sign in'
    });
  }
});

/**
 * Sign up new user
 */
router.post('/signup', async (req, res) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Missing information',
        message: 'Email and password are required'
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName || '',
          roles: ['user'] // Default role
        }
      }
    });

    if (error) {
      console.warn('Sign up failed', { code: error.code, status: error.status });
      return res.status(400).json({
        error: 'Sign up failed',
        message: 'Unable to complete sign up. Please try again.'
      });
    }

    res.json({
      success: true,
      user: data.user,
      session: data.session,
      message: 'Sign up successful'
    });
  } catch (error) {
    console.error('Sign up error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred during sign up'
    });
  }
});

/**
 * Sign out user
 */
router.post('/signout', async (req, res) => {
  try {
    const { error } = await supabase.auth.signOut();

    if (error) {
      console.warn('Sign out failed', { code: error.code, status: error.status });
      return res.status(400).json({
        error: 'Sign out failed',
        message: 'Unable to complete sign out. Please try again.'
      });
    }

    if (req.session) {
      req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({
          success: true,
          message: 'Sign out successful'
        });
      });
      return;
    }

    res.json({
      success: true,
      message: 'Sign out successful'
    });
  } catch (error) {
    console.error('Sign out error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred during sign out'
    });
  }
});

/**
 * Refresh access token
 */
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Missing refresh token',
        message: 'Refresh token is required'
      });
    }

    const session = await refreshAccessToken(refreshToken);

    if (!session) {
      return res.status(401).json({
        error: 'Token refresh failed',
        message: 'Unable to refresh session'
      });
    }

    res.json({
      success: true,
      session,
      message: 'Token refreshed successfully'
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred during token refresh'
    });
  }
});

/**
 * Get current user session
 */
router.get('/session', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    }

    const token = authHeader.replace('Bearer ', '');
    const session = await getUserSession(token);

    if (!session) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required' });
    }

    res.json({
      success: true,
      user: session.user,
      session: {
        access_token: session.access_token,
        expires_at: session.expires_at,
        refresh_token: session.refresh_token ? '***' : undefined // Hide refresh token
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred while checking session'
    });
  }
});

/**
 * Reset password
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Missing email',
        message: 'Email is required for password reset'
      });
    }

    const { error } = await supabase.auth.resetPasswordForEmail(email);

    if (error) {
      console.warn('Password reset request failed', { code: error.code, status: error.status });
      return res.json({
        success: true,
        message: GENERIC_RESET_MESSAGE
      });
    }

    res.json({
      success: true,
      message: GENERIC_RESET_MESSAGE
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An error occurred during password reset'
    });
  }
});

module.exports = router;
