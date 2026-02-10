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
  const modalCloseButton = document.getElementById("modal-close-button");

  let authToken = null;
  let authUser = null;
  let lastFocusedElement = null;

  // Decode JWT payload to check expiration (without verification)
  function decodeJWT(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      
      // Decode base64url payload
      const payload = parts[1];
      let base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
      
      // Add padding if needed (JWT payloads are typically unpadded)
      const padding = base64.length % 4;
      if (padding > 0) {
        base64 += "=".repeat(4 - padding);
      }
      
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
      
      return JSON.parse(jsonPayload);
    } catch (error) {
      console.error("Failed to decode JWT:", error);
      return null;
    }
  }

  // Check if JWT token is expired
  function isTokenExpired(token) {
    const payload = decodeJWT(token);
    
    // Treat tokens with missing or invalid exp as expired
    if (
      !payload ||
      typeof payload.exp !== "number" ||
      !Number.isFinite(payload.exp)
    ) {
      return true;
    }
    
    // exp is in seconds, Date.now() is in milliseconds
    const now = Math.floor(Date.now() / 1000);
    // Token is expired when current time is on or after exp
    return payload.exp <= now;
  }

  // Initialize auth state from localStorage, if available and not expired
  try {
    const storedToken = localStorage.getItem("teacherToken");
    const storedUser = localStorage.getItem("teacherUser");
    
    if (storedToken && storedUser) {
      if (!isTokenExpired(storedToken)) {
        authToken = storedToken;
        authUser = storedUser;
      } else {
        // Token expired, clear localStorage
        localStorage.removeItem("teacherToken");
        localStorage.removeItem("teacherUser");
      }
    } else if (storedToken || storedUser) {
      // Inconsistent auth state, clear both entries to keep storage consistent
      localStorage.removeItem("teacherToken");
      localStorage.removeItem("teacherUser");
    }
  } catch (e) {
    // If accessing localStorage fails (e.g., disabled), start with no auth state
    console.error("Failed to restore auth state:", e);
  }

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
      // Save the currently focused element
      lastFocusedElement = document.activeElement;
      
      authModal.classList.remove("hidden");
      authModal.setAttribute("aria-hidden", "false");
      hideAuthMessage();
      
      // Set initial focus to the first input field or close button
      const usernameInput = document.getElementById("username");
      if (usernameInput && !usernameInput.closest(".hidden")) {
        usernameInput.focus();
      } else {
        modalCloseButton.focus();
      }
    } else {
      authModal.classList.add("hidden");
      authModal.setAttribute("aria-hidden", "true");
      
      // Restore focus to the element that opened the modal
      if (lastFocusedElement) {
        lastFocusedElement.focus();
        lastFocusedElement = null;
      }
    }
  }

  // Handle keyboard navigation in modal (focus trap and Escape key)
  function handleModalKeydown(event) {
    if (event.key === "Escape") {
      toggleAuthModal(false);
      return;
    }

    // Focus trap: keep focus within modal
    if (event.key === "Tab") {
      const focusableElements = authModal.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      const visibleFocusableElements = Array.from(focusableElements).filter(
        (el) => !el.closest(".hidden") && el.offsetParent !== null
      );
      
      if (visibleFocusableElements.length === 0) return;

      const firstElement = visibleFocusableElements[0];
      const lastElement = visibleFocusableElements[visibleFocusableElements.length - 1];

      if (event.shiftKey) {
        // Shift+Tab: moving backwards
        if (document.activeElement === firstElement) {
          event.preventDefault();
          lastElement.focus();
        }
      } else {
        // Tab: moving forwards
        if (document.activeElement === lastElement) {
          event.preventDefault();
          firstElement.focus();
        }
      }
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

        // Create activity name
        const nameHeading = document.createElement("h4");
        nameHeading.textContent = name;
        activityCard.appendChild(nameHeading);

        // Create description
        const descriptionPara = document.createElement("p");
        descriptionPara.textContent = details.description;
        activityCard.appendChild(descriptionPara);

        // Create schedule
        const schedulePara = document.createElement("p");
        const scheduleStrong = document.createElement("strong");
        scheduleStrong.textContent = "Schedule: ";
        schedulePara.appendChild(scheduleStrong);
        schedulePara.appendChild(document.createTextNode(details.schedule));
        activityCard.appendChild(schedulePara);

        // Create availability
        const availabilityPara = document.createElement("p");
        const availabilityStrong = document.createElement("strong");
        availabilityStrong.textContent = "Availability: ";
        availabilityPara.appendChild(availabilityStrong);
        availabilityPara.appendChild(document.createTextNode(`${spotsLeft} spots left`));
        activityCard.appendChild(availabilityPara);

        // Create participants container
        const participantsContainer = document.createElement("div");
        participantsContainer.className = "participants-container";

        if (details.participants.length > 0) {
          const participantsSection = document.createElement("div");
          participantsSection.className = "participants-section";

          const participantsHeading = document.createElement("h5");
          participantsHeading.textContent = "Participants:";
          participantsSection.appendChild(participantsHeading);

          const participantsList = document.createElement("ul");
          participantsList.className = "participants-list";

          details.participants.forEach((email) => {
            const listItem = document.createElement("li");
            
            const emailSpan = document.createElement("span");
            emailSpan.className = "participant-email";
            emailSpan.textContent = email;
            listItem.appendChild(emailSpan);

            if (isLoggedIn) {
              const deleteButton = document.createElement("button");
              deleteButton.className = "delete-btn";
              deleteButton.setAttribute("data-activity", name);
              deleteButton.setAttribute("data-email", email);
              deleteButton.setAttribute("aria-label", `Unregister ${email} from ${name}`);
              deleteButton.textContent = "❌";
              listItem.appendChild(deleteButton);
            }

            participantsList.appendChild(listItem);
          });

          participantsSection.appendChild(participantsList);
          participantsContainer.appendChild(participantsSection);
        } else {
          const noParticipantsPara = document.createElement("p");
          const emElement = document.createElement("em");
          emElement.textContent = "No participants yet";
          noParticipantsPara.appendChild(emElement);
          participantsContainer.appendChild(noParticipantsPara);
        }

        activityCard.appendChild(participantsContainer);
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
      messageDiv.classList.remove("success");
      messageDiv.classList.add("error");
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
        messageDiv.classList.remove("error");
        messageDiv.classList.add("success");

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.classList.remove("success");
        messageDiv.classList.add("error");
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to unregister. Please try again.";
      messageDiv.classList.remove("success");
      messageDiv.classList.add("error");
      messageDiv.classList.remove("hidden");
      console.error("Error unregistering:", error);
    }
  }

  // Handle form submission
  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!authToken) {
      messageDiv.textContent = "Teacher login required to register students.";
      messageDiv.classList.remove("success");
      messageDiv.classList.add("error");
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
        messageDiv.classList.remove("error");
        messageDiv.classList.add("success");
        signupForm.reset();

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.classList.remove("success");
        messageDiv.classList.add("error");
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to sign up. Please try again.";
      messageDiv.classList.remove("success");
      messageDiv.classList.add("error");
      messageDiv.classList.remove("hidden");
      console.error("Error signing up:", error);
    }
  });

  // Initialize app
  adminButton.addEventListener("click", () => toggleAuthModal(true));
  modalCloseButton.addEventListener("click", () => toggleAuthModal(false));
  authModal.addEventListener("click", (event) => {
    if (event.target === authModal) {
      toggleAuthModal(false);
    }
  });
  authModal.addEventListener("keydown", handleModalKeydown);

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
