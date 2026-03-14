document.addEventListener('DOMContentLoaded', () => {
    const actionPanel = document.querySelector('.action-panel');
    const loadingPanel = document.getElementById('loading');
    const resultsPanel = document.getElementById('results');
    const errorPanel = document.getElementById('error');
    
    const scanPageBtn = document.getElementById('scan-page-btn');
    const scanManualBtn = document.getElementById('scan-manual-btn');
    const manualText = document.getElementById('manual-text');
    const backBtn = document.getElementById('back-btn');
    const retryBtn = document.getElementById('retry-btn');
    const errorText = document.getElementById('error-text');

    const API_URL = 'http://127.0.0.1:5001/scan';

    scanPageBtn.addEventListener('click', () => {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (!tabs || !tabs[0]) {
                showError("Unable to access page context.");
                return;
            }
            chrome.scripting.executeScript({
                target: {tabId: tabs[0].id},
                function: getPageText,
            }, (injectionResults) => {
                if (chrome.runtime.lastError) {
                    showError("Scripting Error: " + chrome.runtime.lastError.message);
                    return;
                }
                if (injectionResults && injectionResults[0]) {
                    const text = injectionResults[0].result;
                    if(text.trim().length === 0) {
                        showError("Page context is empty. Try manual inspection.");
                    } else {
                        doScan(text);
                    }
                } else {
                    showError("Failed to extract page context.");
                }
            });
        });
    });

    scanManualBtn.addEventListener('click', () => {
        const text = manualText.value.trim();
        if (text) {
            doScan(text);
        } else {
            showError("Input vector empty. Please provide textual data.");
        }
    });

    backBtn.addEventListener('click', showActionPanel);
    retryBtn.addEventListener('click', showActionPanel);

    function getPageText() {
        return document.body.innerText;
    }

    async function doScan(text) {
        showPanel(loadingPanel);
        try {
            const formData = new FormData();
            formData.append('email_text', text);
            
            const response = await fetch(API_URL, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error("Local Core Offline. Ensure PhishShield server is running on port 5001.");
            }
            
            const data = await response.json();
            displayResults(data);
        } catch (err) {
            showError(err.message || "Unknown error occurred.");
        }
    }

    function displayResults(data) {
        // UI Elements
        const banner = document.getElementById('risk-banner');
        const display = document.getElementById('risk-display');
        const score = document.getElementById('risk-score');
        const mlPred = document.getElementById('ml-pred');
        const kwCount = document.getElementById('kw-count');
        const linkStatus = document.getElementById('link-status');
        const summaryText = document.getElementById('summary-text');

        // Reset classes
        banner.className = 'risk-header';
        
        const riskLevel = data.final_risk.level.toLowerCase();
        
        if (riskLevel === 'critical' || riskLevel === 'high') {
            banner.classList.add('risk-danger');
            display.innerText = riskLevel.toUpperCase() + ' THREAT';
        } else if (riskLevel === 'medium') {
            banner.classList.add('risk-warning');
            display.innerText = 'ELEVATED RISK';
        } else {
            banner.classList.add('risk-safe');
            display.innerText = 'SECURE';
        }

        score.innerText = data.final_risk.score + ' / 100';
        
        mlPred.innerText = data.prediction.label;
        if (data.prediction.label === 'Phishing') mlPred.style.color = 'var(--danger)';
        else mlPred.style.color = 'var(--safe)';

        kwCount.innerText = data.keywords.detected_words ? data.keywords.detected_words.length : 0;
        
        const links = data.links.links || [];
        const suspiciousLinks = links.filter(l => l.suspicious).length;
        if (suspiciousLinks > 0) {
            linkStatus.innerText = suspiciousLinks + " suspicious links found.";
            linkStatus.style.color = 'var(--danger)';
        } else {
            linkStatus.innerText = links.length + " links analyzed (safe).";
            linkStatus.style.color = 'var(--text-primary)';
        }

        summaryText.innerText = data.summary || "Analysis complete.";
        
        showPanel(resultsPanel);
    }

    function showError(msg) {
        errorText.innerText = msg;
        showPanel(errorPanel);
    }

    function showActionPanel() {
        showPanel(actionPanel);
    }

    function showPanel(panel) {
        [actionPanel, loadingPanel, resultsPanel, errorPanel].forEach(p => p.classList.add('hidden'));
        panel.classList.remove('hidden');
    }
});
