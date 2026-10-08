/**
 * SecureShop - Client-Side Enhancements & Laboratory Helpers
 * Red Team / Application Security College Lab
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Auto-dismiss alerts after 6 seconds
    const alerts = document.querySelectorAll(".alert-dismissible");
    alerts.forEach(function (alert) {
        setTimeout(function () {
            try {
                const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
                if (bsAlert) {
                    bsAlert.close();
                }
            } catch (e) {
                // Ignore if already dismissed
            }
        }, 6000);
    });

    // 2. Confirmation prompt for destructive actions (Delete Product / Delete User)
    const deleteButtons = document.querySelectorAll(".btn-delete-confirm");
    deleteButtons.forEach(function (button) {
        button.addEventListener("click", function (event) {
            const itemName = button.getAttribute("data-name") || "this record";
            const confirmed = confirm("Are you sure you want to permanently delete " + itemName + "?");
            if (!confirmed) {
                event.preventDefault();
            }
        });
    });

    // 3. Search input auto-focus and trim
    const searchForm = document.querySelector("form[action*='search']");
    if (searchForm) {
        searchForm.addEventListener("submit", function (e) {
            const input = searchForm.querySelector("input[name='q']");
            if (input) {
                input.value = input.value.trim();
            }
        });
    }

    // 4. Educational Console Message
    console.log(
        "%c[SecureShop Security Lab] Active%c\nThis application is running in an authorized local security testing environment.\nUse OWASP ZAP to inspect HTTP requests, test injection, check headers, and examine session tokens.",
        "background: #1e293b; color: #38bdf8; font-size: 14px; font-weight: bold; padding: 4px 8px; border-radius: 4px;",
        "color: #64748b; font-size: 11px;"
    );
});
