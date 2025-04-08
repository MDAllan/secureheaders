const loginForm = document.getElementById("login-form");
const loginEmail = document.getElementById("login-email");
const loginPassword = document.getElementById("login-password");
const logoutBtn = document.getElementById("logout-btn");
const protectedSection = document.getElementById("protected-section");
const loginSection = document.getElementById("login-section");
const logoutSection = document.getElementById("logout-section");
const ssoSection = document.getElementById("sso-section");

const API_URL = "https://localhost:3000/api/auth";

 // Show the Signup Form and Hide the Login Form
 document.getElementById('show-signup').addEventListener('click', function() {
  document.getElementById('login-section').style.display = 'none';
  document.getElementById('signup-section').style.display = 'block';
});

// Show the Login Form and Hide the Signup Form
document.getElementById('show-login').addEventListener('click', function() {
  document.getElementById('signup-section').style.display = 'none';
  document.getElementById('login-section').style.display = 'block';
});

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

// Select Signup Form Elements
const signupForm = document.getElementById("signup-form");
const signupName = document.getElementById("signup-name");
const signupEmail = document.getElementById("signup-email");
const signupPassword = document.getElementById("signup-password");

// 5. Handle Sign-Up
signupForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const name = signupName.value;
  const email = signupEmail.value;
  const password = signupPassword.value;

  try {
    const res = await fetch(`${API_URL}/signup`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, email, password }),
      credentials: "include", // This ensures cookies are sent with the request
    });

    const data = await res.json();

    if (res.ok) {
      alert("Signup successful! You can now log in.");
      // Optionally, redirect to the login page or log in automatically
      document.getElementById('signup-section').style.display = 'none';
      document.getElementById('login-section').style.display = 'block';
    } else {
      alert(data.msg); // Show error message
    }
  } catch (err) {
    console.error("Signup failed:", err);
  }
});

