document.addEventListener("DOMContentLoaded", async () => {
	const toggle = document.getElementById("focusToggle")
	const statusText = document.getElementById("statusText")
	const storageKey = "ytFocusModeEnabled"


	const result = await chrome.storage.local.get(storageKey)
	const isEnabled = result[storageKey] !== false

	toggle.checked = isEnabled
	updateStatusText(isEnabled)


	toggle.addEventListener("change", async (e) => {
		const newState = e.target.checked
		await chrome.storage.local.set({ [storageKey]: newState })
		updateStatusText(newState)
	})

	function updateStatusText(enabled) {
		statusText.textContent = enabled ? "Focus Mode: ON" : "Focus Mode: OFF"
	}
})
