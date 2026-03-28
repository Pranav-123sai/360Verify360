/* ================================================================
   VERIFY360 — Login Page Script
   login.js
   ================================================================ */

/* ================================================================
   TAB SWITCHING
   ================================================================ */

/**
 * Switch between the Login and Register tabs.
 * @param {'login'|'register'} tab
 */
function switchTab(tab) {
  const loginForm      = document.getElementById("loginForm");
  const registerForm   = document.getElementById("registerForm");
  const loginTabBtn    = document.getElementById("loginTabBtn");
  const registerTabBtn = document.getElementById("registerTabBtn");

  if (tab === "login") {
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
    loginTabBtn.classList.add("active");
    registerTabBtn.classList.remove("active");
    clearErrors();
  } else {
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
    registerTabBtn.classList.add("active");
    loginTabBtn.classList.remove("active");
    clearErrors();
  }
}

/* ================================================================
   PASSWORD VISIBILITY TOGGLE
   ================================================================ */

/**
 * Toggle password field between text and password type.
 * @param {string} inputId - The id of the password input.
 * @param {HTMLElement} btn - The toggle button element.
 */
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === "password") {
    input.type  = "text";
    btn.textContent = "🙈";
  } else {
    input.type  = "password";
    btn.textContent = "👁️";
  }
}

/* ================================================================
   CLIENT-SIDE VALIDATION
   ================================================================ */

/**
 * Validate the register form before submission.
 * Returns true if valid, false otherwise.
 */
function validateRegister(e) {
  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value;
  const confirm  = document.getElementById("regConfirm").value;
  const errorDiv = document.getElementById("registerError");

  // Username: 3–30 chars, alphanumeric + underscore only
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    showError(errorDiv, "Username must be 3–30 characters (letters, numbers, underscores only).");
    e.preventDefault();
    return false;
  }

  // Password length
  if (password.length < 6) {
    showError(errorDiv, "Password must be at least 6 characters.");
    e.preventDefault();
    return false;
  }

  // Passwords must match
  if (password !== confirm) {
    showError(errorDiv, "Passwords do not match.");
    e.preventDefault();
    return false;
  }

  // All good — show loading state
  const btn = document.getElementById("registerBtn");
  btn.disabled    = true;
  btn.textContent = "Creating account…";
  return true;
}

/**
 * Show loading state on the login button.
 */
function handleLoginSubmit() {
  const btn = document.getElementById("loginBtn");
  btn.disabled    = true;
  btn.textContent = "Logging in…";
}

/* ================================================================
   HELPER FUNCTIONS
   ================================================================ */

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
}

function clearErrors() {
  ["loginError", "registerError"].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = "";
      el.classList.add("hidden");
    }
  });
}

/* ================================================================
   BOOT — wire up form event listeners
   ================================================================ */
document.addEventListener("DOMContentLoaded", () => {

  // Register form — client-side validation
  document.getElementById("registerForm")
    .addEventListener("submit", validateRegister);

  // Login form — loading state on submit
  document.getElementById("loginForm")
    .addEventListener("submit", () => handleLoginSubmit());

  // If the URL contains ?tab=register, switch to register tab on load
  const params = new URLSearchParams(window.location.search);
  if (params.get("tab") === "register") {
    switchTab("register");
  }

  // Auto-focus the first visible input
  const firstInput = document.querySelector(".auth-form:not(.hidden) input");
  if (firstInput) firstInput.focus();
});
