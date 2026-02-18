// Authentication state management
class AuthManager {
  constructor() {
    this.isLoggedIn = localStorage.getItem('baseline_auth') === 'true';
    this.user = JSON.parse(localStorage.getItem('baseline_user') || 'null');
  }

  login(userData) {
    this.isLoggedIn = true;
    this.user = userData;
    localStorage.setItem('baseline_auth', 'true');
    localStorage.setItem('baseline_user', JSON.stringify(userData));
  }

  logout() {
    this.isLoggedIn = false;
    this.user = null;
    localStorage.removeItem('baseline_auth');
    localStorage.removeItem('baseline_user');
  }

  getAuthState() {
    return {
      isLoggedIn: this.isLoggedIn,
      user: this.user
    };
  }
}

// Initialize auth manager
const auth = new AuthManager();

// Handle dashboard button clicks
document.addEventListener('DOMContentLoaded', function() {
  // Remove automatic redirection - buttons will work as direct links
  const signinForm = document.querySelector('.signin-form form');
  const signupForm = document.querySelector('.signup-form form');
  
  if (signinForm) {
    signinForm.addEventListener('submit', function(e) {
      e.preventDefault();
      // Simulate login
      const email = document.getElementById('email').value;
      auth.login({ email, name: 'Demo User' });
      alert('Login successful! Redirecting to dashboard...');
      setTimeout(() => {
        window.location.href = './dashboard.html';
      }, 1000);
    });
  }
  
  if (signupForm) {
    signupForm.addEventListener('submit', function(e) {
      e.preventDefault();
      // Simulate signup
      const name = document.getElementById('name').value;
      const email = document.getElementById('email').value;
      auth.login({ name, email });
      alert('Account created! Redirecting to dashboard...');
      setTimeout(() => {
        window.location.href = './dashboard.html';
      }, 1000);
    });
  }
});
