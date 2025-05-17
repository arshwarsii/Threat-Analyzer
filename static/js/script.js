document.addEventListener('DOMContentLoaded', function() {
    // Constants
    const MIN_FILE_SIZE = 1; // Minimum 1 byte
    const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB
    const MAX_ANALYSIS_ATTEMPTS = 10; // 10 attempts (5 minutes total)
    const ANALYSIS_RETRY_DELAY = 30000; // 30 seconds

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
        });
    });
    
    // File Upload Elements
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const selectedFilename = document.getElementById('selected-filename');
    const selectedFileContainer = document.querySelector('.selected-file-container');
    const changeFileBtn = document.getElementById('change-file-btn');
    const fileForm = document.getElementById('file-upload-form');
    
    // URL Analysis Elements
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    
    // Drag and Drop Handlers
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
    
    // File Selection Handlers
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            handleFiles(this.files[0]);
        }
    });
    
    function handleFiles(file) {
        // Validate file size
        if (file.size < MIN_FILE_SIZE) {
            showError('File is too small to analyze (minimum 1 byte required)');
            resetFileInput();
            return;
        }
        
        if (file.size > MAX_FILE_SIZE) {
            showError(`File size exceeds the maximum limit of ${MAX_FILE_SIZE/1024/1024}MB`);
            resetFileInput();
            return;
        }
        
        // Display selected file info
        selectedFilename.textContent = file.name;
        selectedFileContainer.style.display = 'flex';
        uploadArea.style.display = 'none';
    }
    
    // Change file button
    changeFileBtn.addEventListener('click', resetFileInput);
    
    function resetFileInput() {
        fileInput.value = '';
        selectedFileContainer.style.display = 'none';
        uploadArea.style.display = 'block';
    }
    
    // File analysis form submission
    fileForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        if (!fileInput.files.length) {
            showError('Please select a file to analyze');
            return;
        }
        
        const file = fileInput.files[0];
        
        // Revalidate in case something changed
        if (file.size < MIN_FILE_SIZE || file.size > MAX_FILE_SIZE) {
            showError('Invalid file size');
            resetFileInput();
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        analyzeFile(formData, file);
    });
    
    // URL analysis form submission
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }
        
        showProgressIndicator('Analyzing URL...');
        
        fetch('/analyze_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(data => {
            hideProgressIndicator();
            if (data.success) {
                displayResults(data.result);
            } else {
                showError(data.error || 'Unknown error occurred');
            }
        })
        .catch(error => {
            hideProgressIndicator();
            showError('Failed to analyze URL: ' + error.message);
        });
    });
    
    // File Analysis Function
    function analyzeFile(formData, file) {
        showProgressIndicator('Starting analysis...');
        
        fetch('/analyze_file', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (data.success) {
                hideProgressIndicator();
                displayResults(data.result);
            } else {
                if (data.error.includes('submitted for analysis')) {
                    hideProgressIndicator();
                    if (confirm(`${data.error}\n\nWould you like to monitor the analysis progress?`)) {
                        showProgressIndicator('Waiting for analysis to complete...');
                        monitorAnalysis(file);
                    }
                } else {
                    hideProgressIndicator();
                    showError(data.error || 'Unknown error occurred');
                    resetFileInput();
                }
            }
        })
        .catch(error => {
            hideProgressIndicator();
            showError('Failed to analyze file: ' + error.message);
            resetFileInput();
        });
    }
    
    // Analysis Monitoring Function
    function monitorAnalysis(file, attempt = 1) {
        if (attempt > MAX_ANALYSIS_ATTEMPTS) {
            hideProgressIndicator();
            showError('Analysis is taking longer than expected. Please try again later.');
            resetFileInput();
            return;
        }
        
        updateProgressMessage(`Waiting for analysis (attempt ${attempt}/${MAX_ANALYSIS_ATTEMPTS})...`);
        
        const formData = new FormData();
        formData.append('file', file);
        
        fetch('/analyze_file', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (data.success) {
                hideProgressIndicator();
                displayResults(data.result);
            } else {
                if (data.error.includes('submitted for analysis')) {
                    setTimeout(() => {
                        monitorAnalysis(file, attempt + 1);
                    }, ANALYSIS_RETRY_DELAY);
                } else {
                    hideProgressIndicator();
                    showError(data.error || 'Analysis failed');
                    resetFileInput();
                }
            }
        })
        .catch(error => {
            hideProgressIndicator();
            showError('Monitoring failed: ' + error.message);
            resetFileInput();
        });
    }
    
    // Progress Indicator Functions
    function showProgressIndicator(message = 'Processing...') {
        const progressContainer = document.getElementById('progress-container');
        progressContainer.querySelector('p').textContent = message;
        progressContainer.style.display = 'flex';
    }
    
    function updateProgressMessage(message) {
        document.getElementById('progress-container').querySelector('p').textContent = message;
    }
    
    function hideProgressIndicator() {
        document.getElementById('progress-container').style.display = 'none';
    }
    
    // Error Display Function
    function showError(message) {
        alert('Error: ' + message);
    }
    
    // Results Display Function
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
            `👍 ${votes.harmless || 0} | 👎 ${votes.malicious || 0}`;
        
        // Verdict
        document.getElementById('verdict-text').textContent = result.verdict;
        
        // VirusTotal link
        const vtLink = document.getElementById('virustotal-link');
        vtLink.href = result.permalink || '#';
        if (!result.permalink) {
            vtLink.style.display = 'none';
        } else {
            vtLink.style.display = 'inline';
        }
        
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
                
                // Add appropriate icon for each category
                let iconName = 'alert-triangle';
                if (category === 'malware') iconName = 'bug';
                if (category === 'phishing') iconName = 'fish';
                if (category === 'ransomware') iconName = 'lock';
                if (category === 'exploit') iconName = 'hammer';
                
                tag.innerHTML = `<i class="icon" data-lucide="${iconName}"></i> ${formatCategoryName(category)}`;
                categoriesContainer.appendChild(tag);
                lucide.createIcons();
            });
        } else {
            categoriesContainer.innerHTML = '<p><i class="icon" data-lucide="check-circle"></i> No specific threats detected</p>';
            lucide.createIcons();
        }
        
        // Show dashboard
        dashboard.style.display = 'block';
        
        // Scroll to dashboard
        dashboard.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Helper Functions
    function formatCategoryName(category) {
        return category.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }
    
    function truncateString(str, maxLength) {
        if (!str) return 'N/A';
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength) + '...';
    }
    
    // Close results dashboard
    document.querySelector('.close-results').addEventListener('click', function() {
        document.getElementById('results-dashboard').style.display = 'none';
    });

    // Initialize Lucide icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
});
