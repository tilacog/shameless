// Shameless Web Application
// Handles WASM module loading and UI interactions

let wasmModule = null;

// Initialize WASM module
async function initWasm() {
    try {
        const { default: init, wasm_split, wasm_combine, wasm_parse_share, wasm_generate_mnemonic } = await import('./pkg/shameless.js');
        await init();

        wasmModule = {
            split: wasm_split,
            combine: wasm_combine,
            parseShare: wasm_parse_share,
            generateMnemonic: wasm_generate_mnemonic
        };

        // Make generateMnemonic globally accessible for inline HTML scripts
        window.wasmModule = wasmModule;

        console.log('WASM module loaded successfully');
        enableForms();
    } catch (error) {
        console.error('Failed to load WASM module:', error);
        showGlobalError('Failed to load WASM module. Please refresh the page.');
    }
}

// Enable forms after WASM loads
function enableForms() {
    const splitForm = document.getElementById('split-form');
    const combineForm = document.getElementById('combine-form');

    splitForm.addEventListener('submit', handleSplit);
    combineForm.addEventListener('submit', handleCombine);
}

// Handle split form submission
async function handleSplit(event) {
    event.preventDefault();

    const mnemonicInput = document.getElementById('mnemonic-input').value.trim();
    const shares = parseInt(document.getElementById('shares-input').value);
    const threshold = parseInt(document.getElementById('threshold-input').value);

    const splitError = document.getElementById('split-error');
    const splitResult = document.getElementById('split-result');
    const sharesContainer = document.getElementById('shares-container');

    // Clear previous results
    splitError.style.display = 'none';
    splitResult.style.display = 'none';
    sharesContainer.innerHTML = '';

    // Validate inputs
    if (!mnemonicInput) {
        showError(splitError, 'Please enter a mnemonic');
        return;
    }

    const wordCount = mnemonicInput.split(/\s+/).length;
    if (wordCount !== 12 && wordCount !== 24) {
        showError(splitError, `Invalid mnemonic: expected 12 or 24 words, got ${wordCount}`);
        return;
    }

    if (threshold > shares) {
        showError(splitError, 'Threshold cannot be greater than total shares');
        return;
    }

    if (threshold < 2) {
        showError(splitError, 'Threshold must be at least 2');
        return;
    }

    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.textContent;
    submitBtn.textContent = 'Generating...';
    submitBtn.disabled = true;

    try {
        // Call WASM split function
        const resultJson = wasmModule.split(mnemonicInput, shares, threshold);
        const result = JSON.parse(resultJson);

        // Display info
        document.getElementById('split-info').textContent =
            `Created ${result.share_count} shares with threshold ${result.threshold}. ` +
            `You need at least ${result.threshold} shares to reconstruct the secret.`;

        // Display shares
        result.shares.forEach((share, index) => {
            const shareCard = createShareCard(share, index + 1, result.threshold, index);
            sharesContainer.appendChild(shareCard);
        });

        splitResult.style.display = 'block';

    } catch (error) {
        showError(splitError, `Split failed: ${error.message || error}`);
    } finally {
        submitBtn.textContent = originalBtnText;
        submitBtn.disabled = false;
    }
}

// Handle combine form submission
async function handleCombine(event) {
    event.preventDefault();

    const shareInputs = document.querySelectorAll('.share-input');
    const shares = Array.from(shareInputs)
        .map(input => input.value.trim())
        .filter(share => share.length > 0);

    const combineError = document.getElementById('combine-error');
    const combineResult = document.getElementById('combine-result');

    // Clear previous results
    combineError.style.display = 'none';
    combineResult.style.display = 'none';

    if (shares.length === 0) {
        showError(combineError, 'Please enter at least one share');
        return;
    }

    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.textContent;
    submitBtn.textContent = 'Combining...';
    submitBtn.disabled = true;

    try {
        // Call WASM combine function
        const recoveredMnemonic = wasmModule.combine(shares);

        // Display recovered mnemonic
        const mnemonicElement = document.getElementById('recovered-mnemonic');
        mnemonicElement.textContent = recoveredMnemonic;
        mnemonicElement.classList.remove('revealed');

        combineResult.style.display = 'block';

    } catch (error) {
        showError(combineError, `Combine failed: ${error.message || error}`);
    } finally {
        submitBtn.textContent = originalBtnText;
        submitBtn.disabled = false;
    }
}

// Create a share card with metadata and QR code
function createShareCard(shareMnemonic, shareNumber, threshold, shareIndex) {
    const card = document.createElement('div');
    card.className = 'share-card';

    // Parse share metadata
    let metadata = '';
    try {
        const metadataJson = wasmModule.parseShare(shareMnemonic);
        const meta = JSON.parse(metadataJson);
        metadata = `Threshold: ${meta.threshold} | Index: ${meta.share_index} | Words: ${shareMnemonic.split(/\s+/).length}`;
    } catch (e) {
        metadata = `Words: ${shareMnemonic.split(/\s+/).length}`;
    }

    card.innerHTML = `
        <div class="share-header">
            <h4 class="title is-5">Share #${shareNumber}</h4>
            <span class="share-metadata">${metadata}</span>
        </div>
        <div class="share-mnemonic">${shareMnemonic}</div>
        <div class="buttons">
            <button class="button is-link" type="button" onclick="copyShareToClipboard(${shareNumber}, \`${shareMnemonic}\`, this)">
                Copy
            </button>
            <button class="button is-info" type="button" onclick="toggleQRCode(${shareNumber})">
                Show QR Code
            </button>
        </div>
        <div id="qr-container-${shareNumber}" class="qr-container" style="display: none;">
            <div id="qr-code-${shareNumber}" class="qr-code"></div>
        </div>
    `;

    return card;
}

// Copy share to clipboard
window.copyShareToClipboard = async function(shareNumber, shareMnemonic, buttonElement) {
    const button = buttonElement || event.target;

    try {
        await navigator.clipboard.writeText(shareMnemonic);
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    } catch (err) {
        console.error('Clipboard API failed, trying fallback:', err);

        // Fallback for older browsers or permission issues
        const textarea = document.createElement('textarea');
        textarea.value = shareMnemonic;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();

        try {
            const successful = document.execCommand('copy');
            if (successful) {
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                setTimeout(() => {
                    button.textContent = originalText;
                }, 2000);
            } else {
                alert('Failed to copy to clipboard');
            }
        } catch (execErr) {
            console.error('Fallback copy failed:', execErr);
            alert('Failed to copy to clipboard: ' + execErr.message);
        }

        document.body.removeChild(textarea);
    }
};

// Toggle QR code display
window.toggleQRCode = function(shareNumber) {
    const container = document.getElementById(`qr-container-${shareNumber}`);
    const qrDiv = document.getElementById(`qr-code-${shareNumber}`);

    if (container.style.display === 'none') {
        // Show and generate QR code
        container.style.display = 'block';

        // Only generate if not already generated
        if (qrDiv.innerHTML === '') {
            const shareCard = container.closest('.share-card');
            const shareMnemonic = shareCard.querySelector('.share-mnemonic').textContent;

            try {
                new QRCode(qrDiv, {
                    text: shareMnemonic,
                    width: 256,
                    height: 256,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
            } catch (error) {
                qrDiv.innerHTML = '<p style="color: red;">Failed to generate QR code</p>';
            }
        }

        const button = event.target;
        button.textContent = 'Hide QR Code';
    } else {
        // Hide QR code
        container.style.display = 'none';
        const button = event.target;
        button.textContent = 'Show QR Code';
    }
};

// Show error message
function showError(element, message) {
    element.textContent = message;
    element.style.display = 'block';
}

// Show global error (for WASM loading failures)
function showGlobalError(message) {
    const banner = document.createElement('div');
    banner.className = 'notification is-danger';
    banner.style.position = 'fixed';
    banner.style.top = '1rem';
    banner.style.left = '50%';
    banner.style.transform = 'translateX(-50%)';
    banner.style.zIndex = '1000';
    banner.style.maxWidth = '90%';
    banner.textContent = message;
    document.body.appendChild(banner);
}

// Update threshold max when shares change
document.addEventListener('DOMContentLoaded', () => {
    const sharesInput = document.getElementById('shares-input');
    const thresholdInput = document.getElementById('threshold-input');

    sharesInput.addEventListener('input', () => {
        const shares = parseInt(sharesInput.value) || 5;
        thresholdInput.max = shares;
        if (parseInt(thresholdInput.value) > shares) {
            thresholdInput.value = shares;
        }
    });
});

// Initialize on page load
initWasm();
