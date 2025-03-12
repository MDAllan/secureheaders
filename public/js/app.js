const loginForm = document.getElementById("login-form");
const loginEmail = document.getElementById("login-email");
const loginPassword = document.getElementById("login-password");
const logoutBtn = document.getElementById("logout-btn");
const protectedSection = document.getElementById("protected-section");
const loginSection = document.getElementById("login-section");
const logoutSection = document.getElementById("logout-section");
const ssoSection = document.getElementById("sso-section");

const API_URL = "http://localhost:5000/api/auth"; // Update with your API URL

// 1. Handle Login
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = loginEmail.value;
  const password = loginPassword.value;

  try {
    const res = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
      credentials: "include", // This ensures cookies are sent with the request
    });

    const data = await res.json();

    if (res.ok) {
      localStorage.setItem("accessToken", data.token); // Store the JWT token
      loginSection.style.display = "none";
      logoutSection.style.display = "block";
      protectedSection.style.display = "block";
      ssoSection.style.display = "none";
    } else {
      alert(data.msg); // Show error message
    }
  } catch (err) {
    console.error("Login failed:", err);
  }
});

// 2. Handle Logout
logoutBtn.addEventListener("click", async () => {
  try {
    const res = await fetch(`${API_URL}/logout`, {
      method: "POST",
      credentials: "include", // Ensure cookies are sent with the request
    });

    const data = await res.json();

    if (res.ok) {
      localStorage.removeItem("accessToken"); // Remove token
      loginSection.style.display = "block";
      logoutSection.style.display = "none";
      protectedSection.style.display = "none";
    } else {
      alert(data.msg);
    }
  } catch (err) {
    console.error("Logout failed:", err);
  }
});

// 3. Check JWT Token on Page Load to Protect Routes
window.addEventListener("load", () => {
  const token = localStorage.getItem("accessToken");

  if (token) {
    loginSection.style.display = "none";
    logoutSection.style.display = "block";
    protectedSection.style.display = "block";
    ssoSection.style.display = "none";
  } else {
    loginSection.style.display = "block";
    logoutSection.style.display = "none";
    protectedSection.style.display = "none";
    ssoSection.style.display = "block"; // Show Google login option
  }
});

// 4. Handle SSO Authentication with Google
document.getElementById("google-login-btn").addEventListener("click", () => {
  window.location.href = `${API_URL}/google`; // Redirect to Google OAuth
});
