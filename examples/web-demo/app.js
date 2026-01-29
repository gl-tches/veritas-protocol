/**
 * VERITAS Protocol Web Demo
 *
 * Demonstrates the WASM bindings for identity management and safety numbers.
 */

// Import WASM module
import init, {
    WasmClient,
    WasmSafetyNumber,
    version
} from './pkg/veritas_wasm.js';

// Application state
let client = null;
let currentIdentityKeys = null; // Store public keys of current identity

// DOM Elements
const elements = {
    // Status
    status: document.getElementById('status'),
    version: document.getElementById('version'),

    // Unlock section
    unlockSection: document.getElementById('unlock-section'),
    passwordInput: document.getElementById('password'),
    unlockBtn: document.getElementById('unlock-btn'),

    // Main app
    mainApp: document.getElementById('main-app'),

    // Slot info
    slotsUsed: document.getElementById('slots-used'),
    slotsMax: document.getElementById('slots-max'),
    slotsAvailable: document.getElementById('slots-available'),

    // Current identity
    noIdentity: document.getElementById('no-identity'),
    identityDetails: document.getElementById('identity-details'),
    currentHash: document.getElementById('current-hash'),
    copyHashBtn: document.getElementById('copy-hash-btn'),
    identityLabel: document.getElementById('identity-label'),
    identityState: document.getElementById('identity-state'),
    identityExpiry: document.getElementById('identity-expiry'),

    // Create identity
    identityLabelInput: document.getElementById('identity-label-input'),
    createIdentityBtn: document.getElementById('create-identity-btn'),

    // Identity list
    identityList: document.getElementById('identity-list'),

    // Safety number
    peerIdentity: document.getElementById('peer-identity'),
    computeSafetyBtn: document.getElementById('compute-safety-btn'),
    safetyResult: document.getElementById('safety-result'),
    safetyNumeric: document.getElementById('safety-numeric'),
    safetyHex: document.getElementById('safety-hex'),
    qrCanvas: document.getElementById('qr-canvas'),

    // Lock
    lockBtn: document.getElementById('lock-btn')
};

/**
 * Show a status message
 */
function showStatus(message, type = 'info') {
    elements.status.textContent = message;
    elements.status.className = `status ${type}`;
    elements.status.classList.remove('hidden');

    // Auto-hide success messages after 3 seconds
    if (type === 'success') {
        setTimeout(() => {
            elements.status.classList.add('hidden');
        }, 3000);
    }
}

/**
 * Hide the status message
 */
function hideStatus() {
    elements.status.classList.add('hidden');
}

/**
 * Set button loading state
 */
function setButtonLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.innerHTML = '<span class="loading-spinner"></span>Loading...';
    } else {
        button.disabled = false;
        button.textContent = button.dataset.originalText || button.textContent;
    }
}

/**
 * Update the slot info display
 */
async function updateSlotInfo() {
    try {
        const slots = await client.identitySlots();
        elements.slotsUsed.textContent = slots.used;
        elements.slotsMax.textContent = slots.max;
        elements.slotsAvailable.textContent = slots.available;

        // Disable create button if no slots available
        elements.createIdentityBtn.disabled = slots.available <= 0;
    } catch (error) {
        console.error('Failed to update slot info:', error);
    }
}

/**
 * Update the current identity display
 */
function updateCurrentIdentity(identity) {
    if (!identity) {
        elements.noIdentity.classList.remove('hidden');
        elements.identityDetails.classList.add('hidden');
        currentIdentityKeys = null;
        return;
    }

    elements.noIdentity.classList.add('hidden');
    elements.identityDetails.classList.remove('hidden');

    elements.currentHash.textContent = identity.hash;
    elements.identityLabel.textContent = identity.label || 'Unnamed';

    // State badge
    elements.identityState.textContent = identity.state;
    elements.identityState.className = `identity-state ${identity.state.toLowerCase()}`;

    // Expiry info
    if (identity.daysUntilExpiry !== null && identity.daysUntilExpiry !== undefined) {
        elements.identityExpiry.textContent = `Expires in ${identity.daysUntilExpiry} days`;
    } else {
        elements.identityExpiry.textContent = '';
    }
}

/**
 * Update the identity list
 */
async function updateIdentityList() {
    try {
        const identities = await client.listIdentities();
        const currentHash = client.identityHash();

        if (!identities || identities.length === 0) {
            elements.identityList.innerHTML = '<p class="empty-list">No identities created yet.</p>';
            updateCurrentIdentity(null);
            updatePeerSelector([]);
            return;
        }

        // Find and update current identity
        const current = identities.find(id => id.hash === currentHash);
        updateCurrentIdentity(current);

        // Build list HTML
        let html = '';
        for (const identity of identities) {
            const isCurrent = identity.hash === currentHash;
            const shortHash = identity.hash.substring(0, 8) + '...' + identity.hash.substring(56);

            html += `
                <div class="identity-item ${isCurrent ? 'current' : ''}" data-hash="${identity.hash}">
                    <div class="identity-item-info">
                        <span class="identity-item-label">${identity.label || 'Unnamed'}</span>
                        <span class="identity-item-hash">${shortHash}</span>
                    </div>
                    <span class="identity-item-state identity-state ${identity.state.toLowerCase()}">${identity.state}</span>
                </div>
            `;
        }

        elements.identityList.innerHTML = html;

        // Add click handlers
        const items = elements.identityList.querySelectorAll('.identity-item');
        items.forEach(item => {
            item.addEventListener('click', async () => {
                const hash = item.dataset.hash;
                await switchIdentity(hash);
            });
        });

        // Update peer selector for safety number
        updatePeerSelector(identities.filter(id => id.hash !== currentHash));

    } catch (error) {
        console.error('Failed to update identity list:', error);
        showStatus('Failed to load identities: ' + error, 'error');
    }
}

/**
 * Update the peer selector dropdown
 */
function updatePeerSelector(peers) {
    let html = '<option value="">Select a peer identity...</option>';

    for (const peer of peers) {
        const shortHash = peer.hash.substring(0, 8) + '...' + peer.hash.substring(56);
        const label = peer.label || 'Unnamed';
        html += `<option value="${peer.hash}">${label} (${shortHash})</option>`;
    }

    elements.peerIdentity.innerHTML = html;
    elements.computeSafetyBtn.disabled = true;
    elements.safetyResult.classList.add('hidden');
}

/**
 * Switch to a different identity
 */
async function switchIdentity(hash) {
    try {
        await client.switchIdentity(hash);

        // Get and store public keys
        currentIdentityKeys = await client.getPublicKeys();

        await updateIdentityList();
        showStatus('Switched identity successfully', 'success');
    } catch (error) {
        console.error('Failed to switch identity:', error);
        showStatus('Failed to switch identity: ' + error, 'error');
    }
}

/**
 * Create a new identity
 */
async function createIdentity() {
    const label = elements.identityLabelInput.value.trim() || null;

    setButtonLoading(elements.createIdentityBtn, true);

    try {
        const hash = await client.createIdentity(label);

        // Get and store public keys
        currentIdentityKeys = await client.getPublicKeys();

        elements.identityLabelInput.value = '';
        await updateSlotInfo();
        await updateIdentityList();
        showStatus(`Identity created: ${hash.substring(0, 16)}...`, 'success');
    } catch (error) {
        console.error('Failed to create identity:', error);
        showStatus('Failed to create identity: ' + error, 'error');
    } finally {
        setButtonLoading(elements.createIdentityBtn, false);
    }
}

/**
 * Compute safety number between current identity and selected peer
 */
async function computeSafetyNumber() {
    const peerHash = elements.peerIdentity.value;
    if (!peerHash || !currentIdentityKeys) {
        showStatus('Please select a peer identity', 'error');
        return;
    }

    setButtonLoading(elements.computeSafetyBtn, true);

    try {
        // Get peer's public keys by temporarily switching
        const currentHash = client.identityHash();
        await client.switchIdentity(peerHash);
        const peerKeys = await client.getPublicKeys();
        await client.switchIdentity(currentHash);

        // Compute safety number
        const safetyNumber = WasmSafetyNumber.compute(currentIdentityKeys, peerKeys);

        // Display numeric format
        const numericStr = safetyNumber.toNumericString();
        elements.safetyNumeric.textContent = numericStr;

        // Display hex format
        const hexStr = safetyNumber.toQrString();
        elements.safetyHex.textContent = hexStr;

        // Generate QR code
        generateQRCode(hexStr);

        elements.safetyResult.classList.remove('hidden');
        showStatus('Safety number computed successfully', 'success');

    } catch (error) {
        console.error('Failed to compute safety number:', error);
        showStatus('Failed to compute safety number: ' + error, 'error');
    } finally {
        setButtonLoading(elements.computeSafetyBtn, false);
    }
}

/**
 * Generate QR code for the safety number
 */
function generateQRCode(data) {
    // Clear previous QR code
    const container = elements.qrCanvas.parentElement;
    container.innerHTML = '';

    // Create new QR code
    try {
        new QRCode(container, {
            text: data,
            width: 128,
            height: 128,
            colorDark: '#1e293b',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });
    } catch (error) {
        console.error('Failed to generate QR code:', error);
        container.innerHTML = '<p style="color: #991b1b;">QR code generation failed</p>';
    }
}

/**
 * Copy identity hash to clipboard
 */
async function copyHash() {
    const hash = elements.currentHash.textContent;
    if (!hash) return;

    try {
        await navigator.clipboard.writeText(hash);
        showStatus('Hash copied to clipboard', 'success');
    } catch (error) {
        console.error('Failed to copy:', error);
        showStatus('Failed to copy to clipboard', 'error');
    }
}

/**
 * Unlock the wallet
 */
async function unlock() {
    const password = elements.passwordInput.value;
    if (!password) {
        showStatus('Please enter a password', 'error');
        return;
    }

    setButtonLoading(elements.unlockBtn, true);

    try {
        await client.unlock(password);

        elements.unlockSection.classList.add('hidden');
        elements.mainApp.classList.remove('hidden');
        elements.passwordInput.value = '';

        await updateSlotInfo();
        await updateIdentityList();

        // Get current identity keys if available
        if (client.identityHash()) {
            currentIdentityKeys = await client.getPublicKeys();
        }

        hideStatus();
        showStatus('Wallet unlocked successfully', 'success');

    } catch (error) {
        console.error('Failed to unlock:', error);
        showStatus('Failed to unlock wallet: ' + error, 'error');
    } finally {
        setButtonLoading(elements.unlockBtn, false);
    }
}

/**
 * Lock the wallet
 */
async function lock() {
    try {
        await client.lock();

        elements.mainApp.classList.add('hidden');
        elements.unlockSection.classList.remove('hidden');
        currentIdentityKeys = null;

        showStatus('Wallet locked', 'info');

    } catch (error) {
        console.error('Failed to lock:', error);
        showStatus('Failed to lock wallet: ' + error, 'error');
    }
}

/**
 * Initialize the application
 */
async function initApp() {
    showStatus('Initializing WASM module...', 'loading');

    try {
        // Initialize WASM
        await init();

        // Show version
        elements.version.textContent = `v${version()}`;

        // Create client
        client = new WasmClient();

        // Set up event handlers
        elements.unlockBtn.addEventListener('click', unlock);
        elements.lockBtn.addEventListener('click', lock);
        elements.createIdentityBtn.addEventListener('click', createIdentity);
        elements.copyHashBtn.addEventListener('click', copyHash);
        elements.computeSafetyBtn.addEventListener('click', computeSafetyNumber);

        // Password input enter key
        elements.passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') unlock();
        });

        // Peer selector change
        elements.peerIdentity.addEventListener('change', () => {
            elements.computeSafetyBtn.disabled = !elements.peerIdentity.value;
            elements.safetyResult.classList.add('hidden');
        });

        hideStatus();
        console.log('VERITAS Web Demo initialized');

    } catch (error) {
        console.error('Failed to initialize:', error);
        showStatus('Failed to initialize: ' + error + '. Make sure to build the WASM module first.', 'error');
    }
}

// Start the app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
