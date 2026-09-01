document.querySelectorAll("[data-print]").forEach((button) => {
  button.addEventListener("click", () => window.print());
});

// Horizontal-bar chart widths (set via CSSOM — CSP style-src 'self' allows this,
// inline style attributes would not).
document.querySelectorAll(".hbar .fill[data-w]").forEach((el) => {
  const w = parseFloat(el.getAttribute("data-w"));
  if (!Number.isNaN(w)) el.style.width = Math.max(0, Math.min(100, w)) + "%";
});

const header = document.querySelector(".site-header");
const navToggle = document.querySelector(".nav-toggle");
const navLinks = document.querySelectorAll(".site-nav a");
let csrfToken = "";

navToggle?.addEventListener("click", () => {
  const isOpen = header.classList.toggle("nav-open");
  navToggle.setAttribute("aria-expanded", String(isOpen));
  navToggle.setAttribute("aria-label", isOpen ? "Close navigation" : "Open navigation");
});

navLinks.forEach((link) => {
  link.addEventListener("click", () => {
    header.classList.remove("nav-open");
    navToggle?.setAttribute("aria-expanded", "false");
    navToggle?.setAttribute("aria-label", "Open navigation");
  });
});

async function loadCsrfToken() {
  try {
    const response = await fetch("/api/csrf", {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const result = await response.json();
    csrfToken = result.csrfToken || "";
  } catch {
    csrfToken = "";
  }
}

function setFormStatus(form, message, isError = false) {
  const status = form.querySelector(".form-status");
  if (!status) return;
  status.textContent = message;
  status.classList.toggle("is-error", isError);
  status.classList.toggle("is-success", !isError && Boolean(message));
}

function formToPayload(form) {
  const data = new FormData(form);
  return {
    requestType: data.get("requestType"),
    name: data.get("name"),
    email: data.get("email"),
    company: data.get("company"),
    service: data.get("service"),
    timeline: data.get("timeline"),
    message: data.get("message"),
    website: data.get("website"),
  };
}

async function submitInquiry(form) {
  if (!csrfToken) {
    await loadCsrfToken();
  }

  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  setFormStatus(form, "Sending your request...");

  try {
    const response = await fetch("/api/inquiries", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify(formToPayload(form)),
    });

    const result = await response.json();
    if (!response.ok || !result.ok) {
      const message = result.error || (result.errors || []).join(" ") || "Unable to send request.";
      setFormStatus(form, message, true);
      if (response.status === 403) {
        await loadCsrfToken();
      }
      return;
    }

    form.reset();
    setFormStatus(form, result.message || "Thanks. Your request was received.");
  } catch {
    setFormStatus(form, "The request could not be sent. Please try again in a moment.", true);
  } finally {
    submitButton.disabled = false;
  }
}

document.querySelectorAll(".service-request").forEach((link) => {
  link.addEventListener("click", () => {
    const service = link.dataset.service;
    const serviceSelect = document.querySelector('#inquiry-form select[name="service"]');
    if (!serviceSelect || !service) return;

    const matchingOption = Array.from(serviceSelect.options).find((option) => option.value === service);
    if (matchingOption) {
      serviceSelect.value = service;
    }
  });
});

const params = new URLSearchParams(window.location.search);
const requestedService = params.get("service");
const requestedReason = params.get("reason") || params.get("request");
const serviceSelect = document.querySelector('#inquiry-form select[name="service"]');
const reasonField = document.querySelector('#inquiry-form [name="requestType"]');

function setSelectValue(select, value) {
  if (!select || !value) return;
  const match = Array.from(select.options).find((option) => option.value === value);
  if (match) select.value = value;
}

setSelectValue(serviceSelect, requestedService);

if (reasonField && requestedReason) {
  if (reasonField.tagName === "SELECT") {
    setSelectValue(reasonField, requestedReason);
  } else {
    const radio = document.querySelector(`#inquiry-form input[name="requestType"][value="${CSS.escape(requestedReason)}"]`);
    if (radio) radio.checked = true;
  }
}

const contactForms = document.querySelectorAll(".contact-form");

contactForms.forEach((form) => {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    submitInquiry(form);
  });
});

if (contactForms.length > 0) {
  loadCsrfToken();
}
