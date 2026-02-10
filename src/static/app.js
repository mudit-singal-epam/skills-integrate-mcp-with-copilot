document.addEventListener("DOMContentLoaded", () => {
  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const signupForm = document.getElementById("signup-form");
  const signupButton = document.getElementById("signup-button");
  const messageDiv = document.getElementById("message");
  const authButton = document.getElementById("auth-button");
  const authStatus = document.getElementById("auth-status");
  const authModal = document.getElementById("auth-modal");
  const loginForm = document.getElementById("login-form");
  const loginFields = document.getElementById("login-fields");
  const logoutButton = document.getElementById("logout-button");
  const authMessage = document.getElementById("auth-message");
  const emailInput = document.getElementById("email");

  let authToken = localStorage.getItem("userToken");
  let authUser = localStorage.getItem("userName");
  let authRole = localStorage.getItem("userRole");
  let authEmail = localStorage.getItem("userEmail");

  function setAuthUI() {
    const isLoggedIn = Boolean(authToken);
    authStatus.textContent = isLoggedIn
      ? `${authUser} (${authRole})`
      : "Not logged in";
    signupButton.disabled = !isLoggedIn;

    if (isLoggedIn && authRole === "student") {
      emailInput.value = authEmail || "";
      emailInput.disabled = true;
    } else {
      emailInput.disabled = false;
    }

    if (isLoggedIn) {
      loginFields.classList.add("hidden");
      logoutButton.classList.remove("hidden");
    } else {
      loginFields.classList.remove("hidden");
      logoutButton.classList.add("hidden");
    }
  }

  function showMessage(message, isError = false) {
    messageDiv.textContent = message;
    messageDiv.className = isError ? "error" : "success";
    messageDiv.classList.remove("hidden");

    setTimeout(() => {
      messageDiv.classList.add("hidden");
    }, 5000);
  }

  function showAuthMessage(message, isError = false) {
    authMessage.textContent = message;
    authMessage.className = isError ? "error" : "success";
    authMessage.classList.remove("hidden");
  }

  function hideAuthMessage() {
    authMessage.classList.add("hidden");
    authMessage.textContent = "";
  }

  function toggleAuthModal(show) {
    if (show) {
      authModal.classList.remove("hidden");
      authModal.setAttribute("aria-hidden", "false");
      hideAuthMessage();
    } else {
      authModal.classList.add("hidden");
      authModal.setAttribute("aria-hidden", "true");
    }
  }

  function canManageEmail(email) {
    if (!authRole) {
      return false;
    }
    if (authRole === "student") {
      return authEmail === email;
    }
    return authRole === "staff" || authRole === "admin";
  }

  async function fetchActivities() {
    try {
      const response = await fetch("/activities");
      const activities = await response.json();

      activitiesList.innerHTML = "";
      activitySelect.innerHTML = '<option value="">-- Select an activity --</option>';

      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        const spotsLeft =
          details.max_participants - details.participants.length;

        const participantsHTML =
          details.participants.length > 0
            ? `<div class="participants-section">
              <h5>Participants:</h5>
              <ul class="participants-list">
                ${details.participants
                  .map((email) => {
                    const deleteButton = canManageEmail(email)
                      ? `<button class="delete-btn" data-activity="${name}" data-email="${email}">❌</button>`
                      : "";
                    return `<li><span class="participant-email">${email}</span>${deleteButton}</li>`;
                  })
                  .join("")}
              </ul>
            </div>`
            : `<p><em>No participants yet</em></p>`;

        activityCard.innerHTML = `
          <h4>${name}</h4>
          <p>${details.description}</p>
          <p><strong>Schedule:</strong> ${details.schedule}</p>
          <p><strong>Availability:</strong> ${spotsLeft} spots left</p>
          <div class="participants-container">
            ${participantsHTML}
          </div>
        `;

        activitiesList.appendChild(activityCard);

        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        activitySelect.appendChild(option);
      });

      document.querySelectorAll(".delete-btn").forEach((button) => {
        button.addEventListener("click", handleUnregister);
      });
    } catch (error) {
      activitiesList.innerHTML =
        "<p>Failed to load activities. Please try again later.</p>";
      console.error("Error fetching activities:", error);
    }
  }

  async function handleUnregister(event) {
    if (!authToken) {
      showMessage("Login required to unregister students.", true);
      return;
    }

    const button = event.target;
    const activity = button.getAttribute("data-activity");
    const email = button.getAttribute("data-email");

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(activity)}/unregister?email=${encodeURIComponent(email)}`,
        {
          method: "DELETE",
          headers: {
            "X-User-Token": authToken,
          },
        }
      );

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message);
        fetchActivities();
      } else {
        showMessage(result.detail || "An error occurred", true);
      }
    } catch (error) {
      showMessage("Failed to unregister. Please try again.", true);
      console.error("Error unregistering:", error);
    }
  }

  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!authToken) {
      showMessage("Login required to register students.", true);
      return;
    }

    const email = emailInput.value;
    const activity = activitySelect.value;

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(activity)}/signup?email=${encodeURIComponent(email)}`,
        {
          method: "POST",
          headers: {
            "X-User-Token": authToken,
          },
        }
      );

      const result = await response.json();

      if (response.ok) {
        showMessage(result.message);
        if (authRole !== "student") {
          signupForm.reset();
        }
        fetchActivities();
      } else {
        showMessage(result.detail || "An error occurred", true);
      }
    } catch (error) {
      showMessage("Failed to sign up. Please try again.", true);
      console.error("Error signing up:", error);
    }
  });

  authButton.addEventListener("click", () => toggleAuthModal(true));
  authModal.addEventListener("click", (event) => {
    if (event.target === authModal) {
      toggleAuthModal(false);
    }
  });

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideAuthMessage();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const result = await response.json();

      if (response.ok) {
        authToken = result.token;
        authUser = result.username;
        authRole = result.role;
        authEmail = result.email;
        localStorage.setItem("userToken", authToken);
        localStorage.setItem("userName", authUser);
        localStorage.setItem("userRole", authRole);
        localStorage.setItem("userEmail", authEmail);
        setAuthUI();
        showAuthMessage("Logged in successfully.");
        fetchActivities();
      } else {
        showAuthMessage(result.detail || "Login failed.", true);
      }
    } catch (error) {
      showAuthMessage("Login failed. Please try again.", true);
      console.error("Error logging in:", error);
    }
  });

  logoutButton.addEventListener("click", async () => {
    hideAuthMessage();

    try {
      await fetch("/auth/logout", {
        method: "POST",
        headers: {
          "X-User-Token": authToken,
        },
      });
    } catch (error) {
      console.error("Error logging out:", error);
    }

    authToken = null;
    authUser = null;
    authRole = null;
    authEmail = null;
    localStorage.removeItem("userToken");
    localStorage.removeItem("userName");
    localStorage.removeItem("userRole");
    localStorage.removeItem("userEmail");
    setAuthUI();
    showAuthMessage("Logged out.");
    fetchActivities();
  });

  setAuthUI();
  fetchActivities();
});
