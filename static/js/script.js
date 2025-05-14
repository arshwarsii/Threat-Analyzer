// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // Tab Navigation
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.dataset.tab;
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // Show the selected tab pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            
            // Load history when history tab is clicked
            if (tabId === 'history-tab') {
                loadScanHistory();
            }
        });
    });
    
    // File Upload Handling
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const selectedFilename = document.getElementById('selected-filename');
    const selectedFileContainer = document.querySelector('.selected-file-container');
    const changeFileBtn = document.getElementById('change-file-btn');
    const fileForm = document.getElementById('file-upload-form');
    
    // Handle drag and drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, unhighlight, false);
    });
    
    function highlight() {
        uploadArea.classList.add('highlight');
    }
    
    function unhighlight() {
        uploadArea.classList.remove('highlight');
    }
    
    uploadArea.addEventListener('drop', handleDrop, false);
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
            handleFiles(files[0]);
        }
    }
    
    // Handle file selection via browse button
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            handleFiles(this.files[0]);
        }
    });
    
    function handleFiles(file) {
        // Check file size
        if (file.size > 32 * 1024 * 1024) { // 32MB
            alert('File size exceeds the maximum limit of 32MB');
            return;
        }
        
        // Display selected file info
        selectedFilename.textContent = file.name;
        selectedFileContainer.style.display = 'flex';
        uploadArea.style.display = 'none';
    }
    
    // Change file button
    changeFileBtn.addEventListener('click', () => {
        selectedFileContainer.style.display = 'none';
        uploadArea.style.display = 'block';
        fileInput.value = '';
    });
    
    // File analysis form submission
    fileForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        if (!fileInput.files.length) {
            alert('Please select a file to analyze');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        
        showProgressIndicator();
        
        fetch('/analyze_file', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            hideProgressIndicator();
            if (data.success) {
                displayResults(data.result);
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            hideProgressIndicator();
            alert('Error: ' + error.message);
        });
    });
    
    // URL analysis form submission
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a URL to analyze');
            return;
        }
        
        showProgressIndicator();
        
        fetch('/analyze_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            hideProgressIndicator();
            if (data.success) {
                displayResults(data.result);
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => {
            hideProgressIndicator();
            alert('Error: ' + error.message);
        });
    });
    
    // Progress indicator functions
    function showProgressIndicator() {
        document.getElementById('progress-container').style.display = 'flex';
    }
    
    function hideProgressIndicator() {
        document.getElementById('progress-container').style.display = 'none';
    }
    
    // Display results in dashboard
    function displayResults(result) {
        const dashboard = document.getElementById('results-dashboard');
        
        // Fill in the data
        document.getElementById('community-score').textContent = result.community_score;
        document.getElementById('detection-ratio').textContent = `${result.positives}/${result.total}`;
        document.getElementById('resource-value').textContent = truncateString(result.resource, 50);
        document.getElementById('first-seen').textContent = result.first_seen || 'N/A';
        document.getElementById('scan-date').textContent = result.scan_date || 'N/A';
        
        // Community votes
        const votes = result.community_votes || {};
        document.getElementById('community-votes').textContent = 
            `Harmless: ${votes.harmless || 0}, Malicious: ${votes.malicious || 0}`;
        
        // Verdict
        document.getElementById('verdict-text').textContent = result.verdict;
        
        // VirusTotal link
        document.getElementById('virustotal-link').href = result.permalink || '#';
        
        // Fill the gauge
        const gaugeFill = document.getElementById('gauge-fill');
        gaugeFill.style.width = `${result.community_score}%`;
        
        // Set color based on score
        if (result.community_score >= 90) {
            gaugeFill.style.backgroundColor = 'var(--success-color)';
        } else if (result.community_score >= 70) {
            gaugeFill.style.backgroundColor = 'var(--warning-color)';
        } else {
            gaugeFill.style.backgroundColor = 'var(--danger-color)';
        }
        
        // Display threat categories
        const categoriesContainer = document.getElementById('categories-container');
        if (result.threat_categories && result.threat_categories.length > 0) {
            categoriesContainer.innerHTML = '';
            result.threat_categories.forEach(category => {
                const tag = document.createElement('span');
                tag.className = `category-tag ${category}`;
                tag.textContent = formatCategoryName(category);
                categoriesContainer.appendChild(tag);
            });
        } else {
            categoriesContainer.innerHTML = '<p>No specific threats detected</p>';
        }
        
        // Show dashboard
        dashboard.style.display = 'block';
        
        // Scroll to dashboard
        dashboard.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Helper to format category names
    function formatCategoryName(category) {
        return category.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }
    
    // Helper to truncate long strings
    function truncateString(str, maxLength) {
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + '...';
    }
    
    // Close results dashboard
    document.querySelector('.close-results').addEventListener('click', function() {
        document.getElementById('results-dashboard').style.display = 'none';
    });
    
    // Load scan history
    function loadScanHistory() {
        const historyList = document.getElementById('history-list');
        historyList.innerHTML = '<p class="loading-text">Loading history...</p>';
        
        fetch('/history')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.history.length > 0) {
                    historyList.innerHTML = '';
                    
                    data.history.forEach(item => {
                        const historyItem = createHistoryItem(item);
                        historyList.appendChild(historyItem);
                    });
                } else {
                    historyList.innerHTML = '<p class="loading-text">No scan history found</p>';
                }
            })
            .catch(error => {
                historyList.innerHTML = `<p class="loading-text">Error loading history: ${error.message}</p>`;
            });
    }
    
    // Create history item element
    function createHistoryItem(item) {
        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        
        // Format date
        const scanDate = new Date(item.scan_date);
        const formattedDate = scanDate.toLocaleString();
        
        // Determine result class
        let resultClass = 'safe';
        if (item.verdict.includes('High risk')) {
            resultClass = 'high-risk';
        } else if (item.verdict.includes('Moderate risk')) {
            resultClass = 'medium-risk';
        } else if (item.verdict.includes('Low-risk')) {
            resultClass = 'low-risk';
        }
        
        historyItem.innerHTML = `
            <div class="history-item-info">
                <div class="history-resource">${truncateString(item.resource, 50)}</div>
                <div class="history-meta">
                    <div>Type: ${item.scan_type}</div>
                    <div>Date: ${formattedDate}</div>
                    <div>Detection: ${item.positives}/${item.total}</div>
                </div>
            </div>
            <div class="history-result ${resultClass}">
                ${item.verdict.split(':')[0]}
            </div>
        `;
        
        return historyItem;
    }
});