/* ================================================================
   VERIFY360 — Admin Login Script
   admin_login.js
   ================================================================ */

/**
 * Toggle the password field between visible and hidden.
 */
function togglePw() {
  const input  = document.getElementById("password");
  const btn    = document.querySelector(".pw-toggle");

  if (input.type === "password") {
    input.type       = "text";
    btn.textContent  = "🙈";
  } else {
    input.type       = "password";
    btn.textContent  = "👁️";
  }
}

/**
 * Show a loading state on the submit button when the form is submitted.
 */
document.getElementById("adminForm")?.addEventListener("submit", () => {
  const btn       = document.getElementById("submitBtn");
  btn.disabled    = true;
  btn.textContent = "Verifying…";
});
