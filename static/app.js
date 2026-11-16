document.addEventListener("submit", (event) => {
    const message = event.target.querySelector("[data-confirm]");
    if (message && !window.confirm(message.dataset.confirm)) {
        event.preventDefault();
    }
});
