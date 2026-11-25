class FocusModeController {
    constructor() {
        this.storageKey = 'ytFocusModeEnabled';
        this.activeClass = 'yt-focus-active';
        this.init();
    }

    async init() {

        const result = await chrome.storage.local.get(this.storageKey);
        const isEnabled = result[this.storageKey] !== false; 
        
        this.toggleDOMClass(isEnabled);


        chrome.storage.onChanged.addListener(this.handleStorageChange.bind(this));
    }

    handleStorageChange(changes, namespace) {
        if (namespace === 'local' && changes[this.storageKey]) {
            this.toggleDOMClass(changes[this.storageKey].newValue);
        }
    }

    toggleDOMClass(enable) {
        if (enable) {
            document.documentElement.classList.add(this.activeClass);
        } else {
            document.documentElement.classList.remove(this.activeClass);
        }
    }
}

new FocusModeController();