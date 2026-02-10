document.addEventListener("DOMContentLoaded", () => {
  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const signupForm = document.getElementById("signup-form");
  const signupButton = document.getElementById("signup-button");
  const messageDiv = document.getElementById("message");
  const adminButton = document.getElementById("admin-button");
  const adminStatus = document.getElementById("admin-status");
  const authModal = document.getElementById("auth-modal");
  const loginForm = document.getElementById("login-form");
  const loginFields = document.getElementById("login-fields");
  const logoutButton = document.getElementById("logout-button");
  const authMessage = document.getElementById("auth-message");

  let authToken = null;
  let authUser = null;

  function setAuthUI() {
    const isLoggedIn = Boolean(authToken);
    adminStatus.textContent = isLoggedIn
      ? `Logged in as ${authUser}`
      : "Not logged in";
    signupButton.disabled = !isLoggedIn;
    if (isLoggedIn) {
      loginFields.classList.add("hidden");
      logoutButton.classList.remove("hidden");
    } else {
      loginFields.classList.remove("hidden");
      logoutButton.classList.add("hidden");
    }
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

  // Function to fetch activities from API
  async function fetchActivities() {
    try {
      const response = await fetch("/activities");
      const activities = await response.json();

      // Clear loading message
      activitiesList.innerHTML = "";

      // Populate activities list
      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        const spotsLeft =
          details.max_participants - details.participants.length;
        const isLoggedIn = Boolean(authToken);

        // Create participants HTML with delete icons instead of bullet points
        const participantsHTML =
          details.participants.length > 0
            ? `<div class="participants-section">
              <h5>Participants:</h5>
              <ul class="participants-list">
                ${details.participants
                  .map(
                    (email) =>
                      `<li><span class="participant-email">${email}</span>${
                        isLoggedIn
                          ? `<button class="delete-btn" data-activity="${name}" data-email="${email}">❌</button>`
                          : ""
                      }</li>`
                  )
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

        // Add option to select dropdown
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        activitySelect.appendChild(option);
      });

      if (authToken) {
        document.querySelectorAll(".delete-btn").forEach((button) => {
          button.addEventListener("click", handleUnregister);
        });
      }
    } catch (error) {
      activitiesList.innerHTML =
        "<p>Failed to load activities. Please try again later.</p>";
      console.error("Error fetching activities:", error);
    }
  }

  // Handle unregister functionality
  async function handleUnregister(event) {
    if (!authToken) {
      messageDiv.textContent = "Teacher login required to unregister students.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      return;
    }

    const button = event.target;
    const activity = button.getAttribute("data-activity");
    const email = button.getAttribute("data-email");

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(
          activity
        )}/unregister?email=${encodeURIComponent(email)}`,
        {
          method: "DELETE",
          headers: {
            "X-Teacher-Token": authToken,
          },
        }
      );

      const result = await response.json();

      if (response.ok) {
        messageDiv.textContent = result.message;
        messageDiv.className = "success";

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.className = "error";
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to unregister. Please try again.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      console.error("Error unregistering:", error);
    }
  }

  // Handle form submission
  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!authToken) {
      messageDiv.textContent = "Teacher login required to register students.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      return;
    }

    const email = document.getElementById("email").value;
    const activity = document.getElementById("activity").value;

    try {
      const response = await fetch(
        `/activities/${encodeURIComponent(
          activity
        )}/signup?email=${encodeURIComponent(email)}`,
        {
          method: "POST",
          headers: {
            "X-Teacher-Token": authToken,
          },
        }
      );

      const result = await response.json();

      if (response.ok) {
        messageDiv.textContent = result.message;
        messageDiv.className = "success";
        signupForm.reset();

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.className = "error";
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to sign up. Please try again.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      console.error("Error signing up:", error);
    }
  });

  // Initialize app
  adminButton.addEventListener("click", () => toggleAuthModal(true));
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
        localStorage.setItem("teacherToken", authToken);
        localStorage.setItem("teacherUser", authUser);
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
          "X-Teacher-Token": authToken,
        },
      });
    } catch (error) {
      console.error("Error logging out:", error);
    }

    authToken = null;
    authUser = null;
    localStorage.removeItem("teacherToken");
    localStorage.removeItem("teacherUser");
    setAuthUI();
    showAuthMessage("Logged out.");
    fetchActivities();
  });

  setAuthUI();
  fetchActivities();
});
