// Global variables
let riskChart, vulnChart;
let scanResults = [];
let isInitialized = false;
let autoRefreshInterval = null;

// Bulk scanning variables
let csvData = [];
let activeBulkScan = null;

// Parallel scanning configuration - OPTIMIZED FOR MAXIMUM THROUGHPUT
const BULK_SCAN_CONFIG = {
    maxConcurrent: 24,       // Increased from 8 - Maximum concurrent scans
    batchSize: 24,           // Increased from 8 - Process domains in batches  
    retryAttempts: 2,        // Retry failed scans
    retryDelay: 500,         // Reduced from 1000ms - Faster retry cycle
    progressUpdateInterval: 250  // Increased from 500ms - More frequent updates
};

// Apollo.io integration variables
let apolloData = null;
let apolloScannerFormat = null;

// Reset bulk scan UI to pristine state
function resetBulkScanState() {
    console.log('🔄 Resetting bulk scan state...');
    
    // Reset all variables
    activeBulkScan = null;
    csvData = [];
    
    // Reset UI elements
    const csvFileInput = document.getElementById('csvFileInput');
    const csvPreview = document.getElementById('csvPreview');
    const bulkScanBtn = document.getElementById('bulkScanBtn');
    const bulkScanStatus = document.getElementById('bulkScanStatus');
    
    if (csvFileInput) {
        csvFileInput.value = '';
        console.log('✅ CSV file input cleared');
    }
    
    if (csvPreview) {
        csvPreview.style.display = 'none';
        csvPreview.innerHTML = '';
        console.log('✅ CSV preview hidden and cleared');
    }
    
    if (bulkScanBtn) {
        bulkScanBtn.disabled = true;
        console.log('✅ Bulk scan button disabled');
    }
    
    if (bulkScanStatus) {
        bulkScanStatus.innerHTML = '<p class="text-muted mb-0">No bulk scan running</p>';
        console.log('✅ Bulk scan status cleared');
    }
    
    console.log('✅ Bulk scan state completely reset');
}

// Initialize dashboard with error handling
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('Initializing Cyber Insurance Scanner Dashboard...');
        initializeCharts();
        loadDashboardData();
        setupEventHandlers();
        setupAutoRefresh();
        isInitialized = true;
        
        // Make functions globally accessible to ensure onclick handlers work
        window.downloadCsvTemplate = downloadCsvTemplate;
        window.validateCsvFile = validateCsvFile;
        window.startBulkScan = startBulkScan;
        window.showCsvFormat = showCsvFormat;
        window.refreshAllScans = refreshAllScans;
        window.clearAllScans = clearAllScans;
        window.exportAllScans = exportAllScans;
        window.refreshResults = refreshResults;
        
        // Apollo integration functions
        window.uploadApolloFile = uploadApolloFile;
        window.startApolloScan = startApolloScan;
        window.showApolloPreview = showApolloPreview;
        window.resetApolloData = resetApolloData;
        
        // Test function for debugging
        window.testDownload = function() {
            console.log('Test download function called');
            downloadCsvTemplate();
        };
        
        // Initialize bulk scan state
        resetBulkScanState();
        console.log('Bulk scan state initialized');
        
        console.log('Dashboard initialized successfully');
        console.log('Global functions available:', {
            downloadCsvTemplate: typeof window.downloadCsvTemplate,
            validateCsvFile: typeof window.validateCsvFile,
            startBulkScan: typeof window.startBulkScan,
            testDownload: typeof window.testDownload
        });
    } catch (error) {
        console.error('Failed to initialize dashboard:', error);
        showAlert('error', 'Failed to initialize dashboard. Please refresh the page.');
    }
});

// Setup event handlers with error handling
function setupEventHandlers() {
    try {
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', handleScanSubmit);
        }
    } catch (error) {
        console.error('Failed to setup event handlers:', error);
    }
}

// Setup auto-refresh with progress monitoring
function setupAutoRefresh() {
    // Clear any existing interval
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    
    // Refresh every 60 seconds (reduced from 30)
    autoRefreshInterval = setInterval(() => {
        if (isInitialized) {
            loadDashboardData();
            
            // Also check for active scans and show progress
            checkActiveScans();
            
            // Refresh all scans section
            loadAllScans();
        }
    }, 60000);
}

// Handle scan form submission with improved error handling
async function handleScanSubmit(e) {
    e.preventDefault();
    
    try {
        console.log('Scan form submitted');
        
        const domain = document.getElementById('domain').value.trim();
        const companyName = document.getElementById('companyName').value.trim();
        const scanType = document.getElementById('scanType').value;

        console.log('Form data:', { domain, companyName, scanType });

        if (!domain || !companyName) {
            console.log('Missing required fields');
            showAlert('warning', 'Please fill in all required fields');
            return;
        }

        // Clean domain (remove protocol if present)
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '');
        console.log('Clean domain:', cleanDomain);

        showLoading(true);

        const endpoint = scanType === 'quick' ? '/api/scan/quick' : '/api/scan/full';
        console.log('Making request to:', endpoint);
        
        const requestBody = {
            domain: cleanDomain,
            company_name: companyName
        };
        
        console.log('Request body:', requestBody);

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });

        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('HTTP error response:', errorText);
            throw new Error(`HTTP error! status: ${response.status} - ${errorText}`);
        }

        const result = await response.json();
        console.log('Response result:', result);

        if (result.success) {
            if (scanType === 'quick') {
                showAlert('success', `Quick scan completed for ${cleanDomain}!`);
                console.log('Quick scan completed successfully');
            } else {
                // For full scans, get the scan ID and show progress tracking
                showAlert('info', `Full scan started for ${cleanDomain}. Monitoring progress...`);
                console.log('Full scan started successfully');
                
                // Start monitoring scan progress
                startProgressMonitoring();
            }
            
            // Refresh dashboard data after a short delay
            setTimeout(() => {
                loadDashboardData();
            }, 2000);

            // Clear form
            document.getElementById('scanForm').reset();
        } else {
            console.error('Scan failed with success=false:', result);
            throw new Error(result.error || result.message || 'Scan failed');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showAlert('error', 'Scan failed: ' + error.message);
    } finally {
        showLoading(false);
        console.log('Scan process completed');
    }
}

// Show/hide loading spinner
function showLoading(show) {
    try {
        const spinner = document.getElementById('loadingSpinner');
        const form = document.getElementById('scanForm');
        
        if (spinner && form) {
            if (show) {
                spinner.style.display = 'block';
                form.style.opacity = '0.5';
            } else {
                spinner.style.display = 'none';
                form.style.opacity = '1';
            }
        }
    } catch (error) {
        console.error('Error toggling loading state:', error);
    }
}

// Show alert messages with timeout protection
function showAlert(type, message, duration = 5000) {
    try {
        // Create alert div
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert at top of container
        const container = document.querySelector('.container-fluid.p-4');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            
            // Auto dismiss after specified duration
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, duration);
        }
    } catch (error) {
        console.error('Error showing alert:', error);
        // Fallback to browser alert
        alert(message.replace(/<[^>]*>/g, '')); // Strip HTML for browser alert
    }
}

// Start monitoring scan progress
function startProgressMonitoring() {
    // Load progress data every 5 seconds
    const progressInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/scan/progress');
            const data = await response.json();
            
            if (data.success && data.data.scans.length > 0) {
                updateProgressIndicators(data.data.scans);
                
                // Stop monitoring if all scans are complete
                const allComplete = data.data.scans.every(scan => 
                    scan.status === 'completed' || scan.status === 'failed'
                );
                
                if (allComplete) {
                    clearInterval(progressInterval);
                    loadDashboardData(); // Refresh final results
                }
            } else {
                // No active scans, stop monitoring
                clearInterval(progressInterval);
            }
        } catch (error) {
            console.error('Progress monitoring error:', error);
        }
    }, 5000);
    
    // Stop monitoring after 10 minutes max
    setTimeout(() => {
        clearInterval(progressInterval);
    }, 600000);
}

// Update progress indicators in the dashboard
function updateProgressIndicators(scans) {
    try {
        // Check if we have a progress section, if not create one
        let progressSection = document.getElementById('progressSection');
        if (!progressSection) {
            progressSection = createProgressSection();
        }
        
        // Update progress for each active scan
        scans.forEach(scan => {
            updateScanProgressIndicator(scan);
        });
        
    } catch (error) {
        console.error('Error updating progress indicators:', error);
    }
}

// Create progress section in dashboard
function createProgressSection() {
    const container = document.querySelector('.container-fluid.p-4');
    const progressSection = document.createElement('div');
    progressSection.id = 'progressSection';
    progressSection.className = 'row mb-4';
    progressSection.innerHTML = `
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-tasks"></i> Active Scans</h5>
                </div>
                <div class="card-body" id="progressContainer">
                    <!-- Progress indicators will be added here -->
                </div>
            </div>
        </div>
    `;
    
    // Insert after the form section
    const formSection = document.querySelector('.form-card').parentElement.parentElement;
    formSection.parentNode.insertBefore(progressSection, formSection.nextSibling);
    
    return progressSection;
}

// Update individual scan progress indicator
function updateScanProgressIndicator(scan) {
    try {
        let indicatorId = `progress-${scan.scan_id}`;
        let indicator = document.getElementById(indicatorId);
        
        if (!indicator) {
            // Create new progress indicator
            indicator = document.createElement('div');
            indicator.id = indicatorId;
            indicator.className = 'progress-indicator mb-3';
            
            const progressContainer = document.getElementById('progressContainer');
            if (progressContainer) {
                progressContainer.appendChild(indicator);
            }
        }
        
        // Update progress indicator content
        const phaseIcon = getPhaseIcon(scan.current_phase);
        const statusClass = scan.status === 'completed' ? 'success' : 
                           scan.status === 'failed' ? 'danger' : 'primary';
        
        indicator.innerHTML = `
            <div class="d-flex align-items-center justify-content-between p-3 border rounded">
                <div class="d-flex align-items-center">
                    <div class="me-3">
                        <i class="${phaseIcon} text-${statusClass} fa-2x"></i>
                    </div>
                    <div>
                        <div class="fw-bold">${scan.lead.company_name}</div>
                        <div class="text-muted">${scan.lead.domain}</div>
                        <small class="text-info">${scan.current_task}</small>
                    </div>
                </div>
                <div class="text-end">
                    <div class="mb-2">
                        <div class="progress" style="width: 200px; height: 8px;">
                            <div class="progress-bar progress-bar-striped ${scan.status === 'running' ? 'progress-bar-animated' : ''} bg-${statusClass}" 
                                 style="width: ${scan.overall_progress}%"></div>
                        </div>
                        <small class="text-muted">${Math.round(scan.overall_progress)}% • ${formatTime(scan.elapsed_time)}</small>
                    </div>
                    <div>
                        <a href="/scan/${scan.scan_id}" class="btn btn-sm btn-outline-primary" target="_blank">
                            <i class="fas fa-external-link-alt"></i> View Details
                        </a>
                    </div>
                </div>
            </div>
        `;
        
        // Remove completed scans after a delay
        if (scan.status === 'completed' || scan.status === 'failed') {
            setTimeout(() => {
                if (indicator && indicator.parentNode) {
                    indicator.remove();
                    
                    // Remove progress section if no more indicators
                    const progressContainer = document.getElementById('progressContainer');
                    if (progressContainer && progressContainer.children.length === 0) {
                        const progressSection = document.getElementById('progressSection');
                        if (progressSection) {
                            progressSection.remove();
                        }
                    }
                }
            }, 5000);
        }
        
    } catch (error) {
        console.error('Error updating scan progress indicator:', error);
    }
}

// Get icon for scan phase
function getPhaseIcon(phase) {
    const icons = {
        'initializing': 'fas fa-play-circle',
        'asset_discovery': 'fas fa-search',
        'port_scanning': 'fas fa-plug',
        'vulnerability_assessment': 'fas fa-bug',
        'risk_scoring': 'fas fa-calculator',
        'completed': 'fas fa-check-circle',
        'failed': 'fas fa-times-circle'
    };
    return icons[phase] || 'fas fa-cog';
}

// Enhanced format time function
function formatTime(seconds) {
    if (seconds < 60) return Math.round(seconds) + 's';
    const minutes = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${minutes}m ${secs}s`;
}

// Load dashboard data with retry logic
async function loadDashboardData() {
    let retries = 3;
    
    while (retries > 0) {
        try {
            console.log('Loading dashboard data...');
            
            // Load analytics summary with timeout
            const summaryResponse = await fetch('/api/analytics/summary', {
                timeout: 10000
            });
            
            if (summaryResponse.ok) {
                const summaryData = await summaryResponse.json();
                if (summaryData.success) {
                    updateMetrics(summaryData.data);
                    updateCharts(summaryData.data);
                }
            }

            // Load scan results
            const resultsResponse = await fetch('/api/results', {
                timeout: 10000
            });
            
            if (resultsResponse.ok) {
                const resultsData = await resultsResponse.json();
                if (resultsData.success) {
                    displayScanResults(resultsData.data.results);
                }
            }

            // Load executive summary
            const execResponse = await fetch('/api/analytics/executive-summary', {
                timeout: 10000
            });
            
            if (execResponse.ok) {
                const execData = await execResponse.json();
                if (execData.success) {
                    displayExecutiveSummary(execData.data);
                }
            }

            // Load all scans
            await loadAllScans();

            // Load domain summary
            await loadDomainSummary();

            console.log('Dashboard data loaded successfully');
            break; // Success, exit retry loop

        } catch (error) {
            console.error('Error loading dashboard data:', error);
            retries--;
            
            if (retries === 0) {
                console.error('Failed to load dashboard data after retries');
                showAlert('warning', 'Some dashboard data may be outdated. Please refresh if needed.');
            } else {
                // Wait before retry
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
    }
}

// Update metrics cards with error handling
function updateMetrics(data) {
    try {
        const totalScansEl = document.getElementById('totalScans');
        const successRateEl = document.getElementById('successRate');
        const totalVulnsEl = document.getElementById('totalVulns');
        const avgRiskEl = document.getElementById('avgRisk');
        
        if (totalScansEl) totalScansEl.textContent = data.total_scans || 0;
        if (successRateEl) {
            successRateEl.textContent = data.total_scans > 0 ? 
                Math.round((data.completed_scans / data.total_scans) * 100) + '%' : '0%';
        }
        if (totalVulnsEl) totalVulnsEl.textContent = data.total_vulnerabilities || 0;
        
        // Determine average risk level
        const riskDist = data.risk_distribution || {};
        let avgRisk = 'Low';
        if (riskDist.critical > 0) avgRisk = 'Critical';
        else if (riskDist.high > 0) avgRisk = 'High';
        else if (riskDist.medium > 0) avgRisk = 'Medium';
        
        if (avgRiskEl) {
            avgRiskEl.textContent = avgRisk;
            avgRiskEl.className = 'metric-value risk-' + avgRisk.toLowerCase();
        }
    } catch (error) {
        console.error('Error updating metrics:', error);
    }
}

// Initialize charts with error handling
function initializeCharts() {
    try {
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart');
        if (riskCtx) {
            riskChart = new Chart(riskCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#27ae60', '#f39c12', '#e74c3c', '#8e44ad'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }

        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnChart');
        if (vulnCtx) {
            vulnChart = new Chart(vulnCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#8e44ad', '#e74c3c', '#f39c12', '#27ae60'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error initializing charts:', error);
    }
}

// Update charts with new data
function updateCharts(data) {
    try {
        // Update risk distribution chart
        if (riskChart) {
            const riskDist = data.risk_distribution || {};
            riskChart.data.datasets[0].data = [
                riskDist.low || 0,
                riskDist.medium || 0,
                riskDist.high || 0,
                riskDist.critical || 0
            ];
            riskChart.update();
        }

        // Update vulnerability chart
        if (vulnChart) {
            const commonVulns = data.common_vulnerabilities || [];
            const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
            
            commonVulns.forEach(vuln => {
                const severity = vuln.severity.toLowerCase();
                if (vulnCounts.hasOwnProperty(severity)) {
                    vulnCounts[severity] += vuln.count;
                }
            });

            vulnChart.data.datasets[0].data = [
                vulnCounts.critical,
                vulnCounts.high,
                vulnCounts.medium,
                vulnCounts.low
            ];
            vulnChart.update();
        }
    } catch (error) {
        console.error('Error updating charts:', error);
    }
}

// Display scan results with enhanced progress linking
function displayScanResults(results) {
    try {
        const container = document.getElementById('scanResults');
        if (!container) return;
        
        if (!results || results.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">No scan results available. Start a new scan to see results here.</p>';
            return;
        }

        let html = '';
        results.slice(0, 5).forEach(result => { // Show last 5 results
            const riskClass = 'risk-' + result.risk_score.risk_category;
            const riskBadgeClass = getRiskBadgeClass(result.risk_score.risk_category);
            
            html += `
                <div class="scan-result-card">
                    <div class="row align-items-center">
                        <div class="col-md-3">
                            <h5 class="mb-1">${escapeHtml(result.lead.domain)}</h5>
                            <small class="text-muted">${escapeHtml(result.lead.company_name)}</small>
                        </div>
                        <div class="col-md-2">
                            <span class="status-badge ${riskBadgeClass}">
                                ${result.risk_score.risk_category.toUpperCase()}
                            </span>
                        </div>
                        <div class="col-md-2">
                            <div class="text-center">
                                <div class="h4 ${riskClass} mb-0">${result.risk_score.overall_score}</div>
                                <small>Risk Score</small>
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="text-center">
                                <div class="h5 mb-0">${result.risk_score.total_vulnerabilities}</div>
                                <small>Vulnerabilities</small>
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="text-center">
                                <div class="h5 mb-0">${result.risk_score.total_assets}</div>
                                <small>Assets</small>
                            </div>
                        </div>
                        <div class="col-md-1">
                            <div class="dropdown">
                                <button class="btn btn-sm btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <ul class="dropdown-menu">
                                    <li><a class="dropdown-item" href="/scan/${result.scan_id}" target="_blank">
                                        <i class="fas fa-external-link-alt me-2"></i>View Details
                                    </a></li>
                                    <li><a class="dropdown-item" href="#" onclick="showDetailedResults('${result.scan_id}')">
                                        <i class="fas fa-download me-2"></i>Export Results
                                    </a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    ${result.vulnerabilities && result.vulnerabilities.length > 0 ? 
                        `<div class="mt-3">
                            <small class="text-muted">Recent Vulnerabilities:</small>
                            ${result.vulnerabilities.slice(0, 2).map(vuln => `
                                                            <div class="vulnerability-item vulnerability-${escapeHtml(vuln.severity.toLowerCase())} mt-2">
                                <strong>${escapeHtml(vuln.cve_id)}</strong> - ${escapeHtml(vuln.description)}
                                <span class="badge bg-${getSeverityColor(vuln.severity)} ms-2">${escapeHtml(vuln.severity)}</span>
                                </div>
                            `).join('')}
                        </div>` : ''
                    }
                </div>
            `;
        });

        container.innerHTML = html;
    } catch (error) {
        console.error('Error displaying scan results:', error);
    }
}

// Display executive summary with error handling
function displayExecutiveSummary(data) {
    try {
        const container = document.getElementById('executiveSummary');
        if (!container) return;
        
        let html = `
            <div class="row">
                <div class="col-md-6">
                    <h5><i class="fas fa-chart-line"></i> Scan Overview</h5>
                    <ul class="list-unstyled">
                        <li><strong>Domains Scanned:</strong> ${data.scan_overview.total_domains_scanned}</li>
                        <li><strong>Success Rate:</strong> ${data.scan_overview.success_rate_percentage}%</li>
                        <li><strong>Avg Scan Time:</strong> ${data.scan_overview.avg_scan_duration_minutes} min</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h5><i class="fas fa-exclamation-triangle"></i> Risk Assessment</h5>
                    <ul class="list-unstyled">
                        <li><strong>High Risk Domains:</strong> ${data.risk_assessment.high_risk_domains_count}</li>
                        <li><strong>Total Vulnerabilities:</strong> ${data.security_findings.total_vulnerabilities}</li>
                        <li><strong>Immediate Attention:</strong> ${data.risk_assessment.requires_immediate_attention}</li>
                    </ul>
                </div>
            </div>
        `;

        if (data.recommendations && data.recommendations.length > 0) {
            html += `
                <div class="mt-4">
                    <h5><i class="fas fa-lightbulb"></i> Key Recommendations</h5>
                    <ul>
                        ${data.recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        container.innerHTML = html;
    } catch (error) {
        console.error('Error displaying executive summary:', error);
    }
}

// Helper functions
function getRiskBadgeClass(risk) {
    const classes = {
        low: 'bg-success',
        medium: 'bg-warning',
        high: 'bg-danger',
        critical: 'bg-dark'
    };
    return classes[risk] || 'bg-secondary';
}

function getSeverityColor(severity) {
    const colors = {
        LOW: 'success',
        MEDIUM: 'warning',
        HIGH: 'danger',
        CRITICAL: 'dark'
    };
    return colors[severity] || 'secondary';
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Show detailed results
function showDetailedResults(scanId) {
    try {
        window.open(`/api/export/json/${scanId}`, '_blank');
    } catch (error) {
        console.error('Error opening detailed results:', error);
        showAlert('error', 'Failed to open detailed results');
    }
}

// Refresh results
function refreshResults() {
    try {
        loadDashboardData();
        showAlert('info', 'Dashboard refreshed!');
    } catch (error) {
        console.error('Error refreshing results:', error);
        showAlert('error', 'Failed to refresh dashboard');
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
});

// Check for active scans and start monitoring if needed
async function checkActiveScans() {
    try {
        const response = await fetch('/api/scan/progress');
        const data = await response.json();
        
        if (data.success && data.data.scans.length > 0) {
            updateProgressIndicators(data.data.scans);
        }
    } catch (error) {
        console.error('Error checking active scans:', error);
    }
}

// Load and display all scans
async function loadAllScans() {
    try {
        console.log('Loading all scans...');
        const response = await fetch('/api/scans/all');
        const data = await response.json();
        
        if (data.success) {
            displayAllScans(data.data.scans);
        } else {
            throw new Error(data.error || 'Failed to load scans');
        }
    } catch (error) {
        console.error('Error loading all scans:', error);
        displayAllScansError(error.message);
    }
}

// Display all scans in the UI
function displayAllScans(scans) {
    const container = document.getElementById('allScansContainer');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = '<p class="text-muted text-center">No scans found. Start a new scan to see results here.</p>';
        updateScanCountBadge(0);
        return;
    }
    
    // Update scan count badge
    updateScanCountBadge(scans.length);
    
    // Add search and summary at the top
    const summaryHtml = createScansSummaryHtml(scans);
    const searchHtml = createScanSearchHtml();
    const scansHtml = scans.map(scan => createScanItemHtml(scan)).join('');
    
    container.innerHTML = `
        ${summaryHtml}
        ${searchHtml}
        <div id="scansListContainer">
            ${scansHtml}
        </div>
    `;
    
    // Add search functionality
    setupScanSearch(scans);
}

// Create HTML for a single scan item
function createScanItemHtml(scan) {
    const statusClass = getStatusClass(scan.status);
    const progressValue = scan.overall_progress || 0;
    const riskBadge = getRiskBadgeHtml(scan);
    const timeInfo = getTimeInfoHtml(scan);
    const actions = getScanActionsHtml(scan);
    const riskInfo = getRiskInfoHtml(scan);
    
    return `
        <div class="scan-item ${statusClass}">
            <div class="scan-header">
                <div class="flex-grow-1">
                    <div class="d-flex align-items-center justify-content-between">
                        <div>
                            <div class="scan-domain">${escapeHtml(scan.domain)}</div>
                            <div class="scan-company">${escapeHtml(scan.company_name || 'Unknown Company')}</div>
                        </div>
                        <div class="scan-meta">
                            <small class="text-muted">
                                <i class="fas fa-calendar"></i> ${formatScanDate(scan.started_at)}
                            </small>
                            ${scan.scan_id ? `<br><small class="text-muted">ID: ${scan.scan_id.substring(0, 8)}...</small>` : ''}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="scan-status">
                <div class="status-indicator">
                    <i class="fas ${getStatusIcon(scan.status)}"></i>
                    <span class="ms-2">${getStatusText(scan)}</span>
                    ${scan.scan_type ? `<span class="badge bg-secondary ms-2">${scan.scan_type}</span>` : ''}
                </div>
                
                <div class="progress-container">
                    <div class="progress-text">${scan.current_phase || 'Initializing'} - ${progressValue}%</div>
                    <div class="progress" style="height: 8px;">
                        <div class="progress-bar ${getProgressBarClass(scan.status)}" 
                             role="progressbar" 
                             style="width: ${progressValue}%" 
                             aria-valuenow="${progressValue}" 
                             aria-valuemin="0" 
                             aria-valuemax="100">
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="scan-footer">
                <div class="scan-details">
                    ${riskInfo}
                    ${timeInfo}
                </div>
                <div class="scan-actions">
                    ${riskBadge}
                    ${actions}
                </div>
            </div>
        </div>
    `;
}

// Get CSS class for scan status
function getStatusClass(status) {
    switch (status) {
        case 'active':
        case 'running':
        case 'in_progress':
            return 'active';
        case 'completed':
            return 'completed';
        case 'failed':
        case 'error':
            return 'failed';
        default:
            return '';
    }
}

// Get icon for scan status
function getStatusIcon(status) {
    switch (status) {
        case 'active':
        case 'running':
        case 'in_progress':
            return 'fa-spinner fa-spin';
        case 'completed':
            return 'fa-check-circle';
        case 'failed':
        case 'error':
            return 'fa-exclamation-circle';
        default:
            return 'fa-question-circle';
    }
}

// Get status text
function getStatusText(scan) {
    switch (scan.status) {
        case 'active':
        case 'running':
        case 'in_progress':
            return 'Running';
        case 'completed':
            return 'Completed';
        case 'failed':
        case 'error':
            return 'Failed';
        default:
            return 'Unknown';
    }
}

// Get progress bar class
function getProgressBarClass(status) {
    switch (status) {
        case 'active':
        case 'running':
        case 'in_progress':
            return 'bg-primary';
        case 'completed':
            return 'bg-success';
        case 'failed':
        case 'error':
            return 'bg-danger';
        default:
            return 'bg-secondary';
    }
}

// Get risk badge HTML
function getRiskBadgeHtml(scan) {
    if (!scan.risk_level || scan.status !== 'completed') {
        return '';
    }
    
    return `<span class="risk-badge risk-${scan.risk_level}">${scan.risk_level}</span>`;
}

// Get time information HTML
function getTimeInfoHtml(scan) {
    let timeHtml = '';
    
    if (scan.started_at) {
        const startTime = new Date(scan.started_at).toLocaleString();
        timeHtml += `<div class="scan-timestamp"><i class="fas fa-play"></i> Started: ${startTime}</div>`;
    }
    
    if (scan.completed_at) {
        const endTime = new Date(scan.completed_at).toLocaleString();
        const duration = getDurationBetween(scan.started_at, scan.completed_at);
        timeHtml += `<div class="scan-timestamp"><i class="fas fa-flag-checkered"></i> Completed: ${endTime} (${duration})</div>`;
    }
    
    return timeHtml;
}

// Get risk information HTML
function getRiskInfoHtml(scan) {
    if (!scan.risk_score || scan.status !== 'completed') {
        return '';
    }
    
    const riskScore = scan.risk_score;
    return `
        <div class="risk-info">
            <small class="text-muted">
                <i class="fas fa-shield-alt"></i> Risk Score: ${riskScore.overall_score || 'N/A'}/100
                ${riskScore.total_vulnerabilities ? `| <i class="fas fa-bug"></i> ${riskScore.total_vulnerabilities} vuln(s)` : ''}
            </small>
        </div>
    `;
}

// Format scan date for display
function formatScanDate(dateString) {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
}

// Get duration between two dates
function getDurationBetween(startDate, endDate) {
    if (!startDate || !endDate) return 'Unknown';
    
    const start = new Date(startDate);
    const end = new Date(endDate);
    const diffMs = end - start;
    
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    
    if (diffMins < 1) return '<1m';
    if (diffMins < 60) return `${diffMins}m`;
    
    const hours = Math.floor(diffMins / 60);
    const mins = diffMins % 60;
    return `${hours}h ${mins}m`;
}

// Get scan actions HTML
function getScanActionsHtml(scan) {
    let actions = '';
    
    // Add cancel button for running scans
    if (scan.status === 'running' || scan.status === 'active' || scan.status === 'in_progress') {
        actions += `
            <button class="btn btn-outline-danger btn-sm" onclick="cancelScan('${scan.scan_id}')" title="Cancel Scan">
                <i class="fas fa-times"></i>
            </button>
        `;
    }
    
    // Add export button for completed scans
    if (scan.status === 'completed') {
        actions += `
            <div class="btn-group">
                <button type="button" class="btn btn-outline-success btn-sm dropdown-toggle" data-bs-toggle="dropdown" title="Export Scan">
                    <i class="fas fa-download"></i>
                </button>
                <ul class="dropdown-menu">
                    <li><a class="dropdown-item" href="#" onclick="exportScan('${scan.scan_id}', 'json')">
                        <i class="fas fa-code"></i> JSON
                    </a></li>
                    <li><a class="dropdown-item" href="#" onclick="exportScan('${scan.scan_id}', 'csv')">
                        <i class="fas fa-table"></i> CSV  
                    </a></li>
                    <li><a class="dropdown-item" href="#" onclick="exportScan('${scan.scan_id}', 'pdf')">
                        <i class="fas fa-file-pdf"></i> PDF
                    </a></li>
                </ul>
            </div>
        `;
    }
    
    // Add view details button
    actions += `
        <a href="/scan/${scan.scan_id}" class="btn btn-primary btn-view-scan">
            <i class="fas fa-eye"></i> View Details
        </a>
    `;
    
    return actions;
}

// Create scans summary HTML
function createScansSummaryHtml(scans) {
    const activeScans = scans.filter(s => ['active', 'running', 'in_progress'].includes(s.status));
    const completedScans = scans.filter(s => s.status === 'completed');
    const failedScans = scans.filter(s => ['failed', 'error'].includes(s.status));
    
    return `
        <div class="scans-summary mb-3">
            <div class="row text-center">
                <div class="col-md-3">
                    <div class="summary-card">
                        <i class="fas fa-list text-primary"></i>
                        <div class="summary-number">${scans.length}</div>
                        <div class="summary-label">Total Scans</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="summary-card">
                        <i class="fas fa-spinner text-info"></i>
                        <div class="summary-number">${activeScans.length}</div>
                        <div class="summary-label">Active</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="summary-card">
                        <i class="fas fa-check-circle text-success"></i>
                        <div class="summary-number">${completedScans.length}</div>
                        <div class="summary-label">Completed</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="summary-card">
                        <i class="fas fa-exclamation-circle text-danger"></i>
                        <div class="summary-number">${failedScans.length}</div>
                        <div class="summary-label">Failed</div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Create scan search HTML
function createScanSearchHtml() {
    return `
        <div class="scan-search mb-3">
            <div class="row">
                <div class="col-md-6">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" id="scanSearchInput" class="form-control" placeholder="Search by domain or company name..." autocomplete="off">
                    </div>
                </div>
                <div class="col-md-3">
                    <select id="scanStatusFilter" class="form-select">
                        <option value="">All Status</option>
                        <option value="running">Active</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <select id="scanSortOrder" class="form-select">
                        <option value="newest">Newest First</option>
                        <option value="oldest">Oldest First</option>
                        <option value="domain">Domain A-Z</option>
                        <option value="company">Company A-Z</option>
                    </select>
                </div>
            </div>
        </div>
    `;
}

// Setup scan search functionality
function setupScanSearch(scans) {
    const searchInput = document.getElementById('scanSearchInput');
    const statusFilter = document.getElementById('scanStatusFilter');
    const sortOrder = document.getElementById('scanSortOrder');
    
    function filterAndSortScans() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedStatus = statusFilter.value;
        const selectedSort = sortOrder.value;
        
        let filteredScans = scans.filter(scan => {
            const matchesSearch = !searchTerm || 
                scan.domain.toLowerCase().includes(searchTerm) ||
                scan.company_name.toLowerCase().includes(searchTerm);
            
            const matchesStatus = !selectedStatus || 
                (selectedStatus === 'running' && ['active', 'running', 'in_progress'].includes(scan.status)) ||
                (selectedStatus === 'completed' && scan.status === 'completed') ||
                (selectedStatus === 'failed' && ['failed', 'error'].includes(scan.status));
            
            return matchesSearch && matchesStatus;
        });
        
        // Sort scans
        filteredScans.sort((a, b) => {
            switch (selectedSort) {
                case 'oldest':
                    return (a.started_at || '').localeCompare(b.started_at || '');
                case 'domain':
                    return a.domain.localeCompare(b.domain);
                case 'company':
                    return a.company_name.localeCompare(b.company_name);
                case 'newest':
                default:
                    return (b.started_at || '').localeCompare(a.started_at || '');
            }
        });
        
        // Update the display
        const container = document.getElementById('scansListContainer');
        const scansHtml = filteredScans.map(scan => createScanItemHtml(scan)).join('');
        container.innerHTML = scansHtml || '<p class="text-muted text-center mt-4">No scans match your filters.</p>';
        
        // Update the search results count
        updateSearchResultsCount(filteredScans.length, scans.length);
    }
    
    // Add event listeners
    searchInput.addEventListener('input', filterAndSortScans);
    statusFilter.addEventListener('change', filterAndSortScans);
    sortOrder.addEventListener('change', filterAndSortScans);
}

// Update search results count
function updateSearchResultsCount(filteredCount, totalCount) {
    const existingCounter = document.querySelector('.search-results-count');
    if (existingCounter) {
        existingCounter.remove();
    }
    
    if (filteredCount !== totalCount) {
        const counter = document.createElement('div');
        counter.className = 'search-results-count text-muted text-center mb-2';
        counter.innerHTML = `<small><i class="fas fa-filter"></i> Showing ${filteredCount} of ${totalCount} scans</small>`;
        
        const container = document.getElementById('scansListContainer');
        container.parentNode.insertBefore(counter, container);
    }
}

// Update scan count badge in header
function updateScanCountBadge(count) {
    const header = document.querySelector('#allScansContainer').closest('.chart-container').querySelector('h4');
    
    // Remove existing badge
    const existingBadge = header.querySelector('.scan-count-badge');
    if (existingBadge) {
        existingBadge.remove();
    }
    
    // Add new badge
    if (count > 0) {
        const badge = document.createElement('span');
        badge.className = 'scan-count-badge badge bg-primary ms-2';
        badge.textContent = count;
        header.appendChild(badge);
    }
}

// Display error message for all scans
function displayAllScansError(errorMessage) {
    const container = document.getElementById('allScansContainer');
    container.innerHTML = `
        <div class="alert alert-warning text-center">
            <i class="fas fa-exclamation-triangle"></i>
            Error loading scans: ${escapeHtml(errorMessage)}
        </div>
    `;
}

// Refresh all scans data
async function refreshAllScans() {
    const refreshBtn = document.querySelector('[onclick="refreshAllScans()"]');
    if (refreshBtn) {
        refreshBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Refreshing...';
        refreshBtn.disabled = true;
    }
    
    try {
        await loadAllScans();
    } finally {
        if (refreshBtn) {
            refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
            refreshBtn.disabled = false;
        }
    }
}

// Clear all scans
async function clearAllScans() {
    if (!confirm('Are you sure you want to clear ALL scans? This will cancel all running scans and delete all scan results. This action cannot be undone.')) {
        return;
    }
    
    const clearBtn = document.querySelector('[onclick="clearAllScans()"]');
    if (clearBtn) {
        clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
        clearBtn.disabled = true;
    }
    
    try {
        const response = await fetch('/api/scans/clear-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            console.log('Cleared scans:', result.data);
            
            // Show success message
            showNotification(`Cleared ${result.data.total_cleared} scans successfully`, 'success');
            
            // Refresh the dashboard
            await loadAllScans();
            await loadDashboardData();
        } else {
            showNotification('Failed to clear scans: ' + result.message, 'error');
        }
    } catch (error) {
        console.error('Error clearing scans:', error);
        showNotification('Error clearing scans: ' + error.message, 'error');
    } finally {
        if (clearBtn) {
            clearBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Clear All';
            clearBtn.disabled = false;
        }
    }
}

// Cancel individual scan
async function cancelScan(scanId) {
    if (!confirm('Are you sure you want to cancel this scan?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/scan/${scanId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification(`Scan cancelled successfully`, 'success');
            await loadAllScans();
        } else {
            showNotification('Failed to cancel scan: ' + result.message, 'error');
        }
    } catch (error) {
        console.error('Error cancelling scan:', error);
        showNotification('Error cancelling scan: ' + error.message, 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'info'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Export all scans
async function exportAllScans() {
    const exportBtn = document.querySelector('[onclick="exportAllScans()"]');
    if (exportBtn) {
        exportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Exporting...';
        exportBtn.disabled = true;
    }
    
    try {
        // Show export format selection modal
        const format = await showExportModal();
        if (!format) {
            return; // User cancelled
        }
        
        // Get all scans data
        const response = await fetch('/api/scans/all');
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch scans');
        }
        
        const scans = result.data.scans || [];
        
        if (scans.length === 0) {
            showNotification('No scans to export', 'warning');
            return;
        }
        
        // Export based on format
        if (format === 'json') {
            exportAsJSON(scans, 'all_scans');
        } else if (format === 'csv') {
            exportAsCSV(scans, 'all_scans');
        } else if (format === 'pdf') {
            await exportAsPDF(scans, 'all_scans');
        }
        
        showNotification(`Exported ${scans.length} scans as ${format.toUpperCase()}`, 'success');
        
    } catch (error) {
        console.error('Error exporting scans:', error);
        showNotification('Error exporting scans: ' + error.message, 'error');
    } finally {
        if (exportBtn) {
            exportBtn.innerHTML = '<i class="fas fa-download"></i> Export All';
            exportBtn.disabled = false;
        }
    }
}

// Show export format selection modal
function showExportModal() {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Export Format</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>Choose the export format:</p>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-primary" onclick="selectFormat('json')">
                                <i class="fas fa-code"></i> JSON Format
                            </button>
                            <button class="btn btn-outline-success" onclick="selectFormat('csv')">
                                <i class="fas fa-table"></i> CSV Format
                            </button>
                            <button class="btn btn-outline-danger" onclick="selectFormat('pdf')">
                                <i class="fas fa-file-pdf"></i> PDF Report
                            </button>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        
        window.selectFormat = (format) => {
            bsModal.hide();
            resolve(format);
        };
        
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
            delete window.selectFormat;
            resolve(null);
        });
        
        bsModal.show();
    });
}

// Export as JSON
function exportAsJSON(data, filename) {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    downloadBlob(blob, `${filename}_${getTimestamp()}.json`);
}

// Export as CSV
function exportAsCSV(scans, filename) {
    if (!scans || scans.length === 0) {
        return;
    }
    
    // CSV headers
    const headers = [
        'Scan ID',
        'Domain', 
        'Company',
        'Status',
        'Risk Level',
        'Risk Score',
        'Total Assets',
        'Total Vulnerabilities',
        'Open Ports',
        'Started At',
        'Completed At',
        'Duration (seconds)'
    ];
    
    // Convert scans to CSV rows
    const rows = scans.map(scan => [
        scan.scan_id || '',
        scan.domain || '',
        scan.company_name || '',
        scan.status || '',
        scan.risk_level || '',
        scan.risk_score || '',
        scan.total_assets || 0,
        scan.total_vulnerabilities || 0,
        scan.total_open_ports || 0,
        scan.started_at || '',
        scan.completed_at || '',
        scan.scan_duration || ''
    ]);
    
    // Combine headers and rows
    const csvContent = [headers, ...rows]
        .map(row => row.map(field => `"${field}"`).join(','))
        .join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    downloadBlob(blob, `${filename}_${getTimestamp()}.csv`);
}

// Export as PDF (simplified version)
async function exportAsPDF(scans, filename) {
    // For now, create a simple HTML report and let browser handle PDF generation
    const htmlContent = generateHTMLReport(scans);
    
    // Open in new window for printing/saving as PDF
    const printWindow = window.open('', '_blank');
    printWindow.document.write(htmlContent);
    printWindow.document.close();
    printWindow.focus();
    
    // Auto-trigger print dialog
    setTimeout(() => {
        printWindow.print();
    }, 500);
}

// Generate HTML report
function generateHTMLReport(scans) {
    const completedScans = scans.filter(scan => scan.status === 'completed');
    const totalScans = scans.length;
    const avgRiskScore = completedScans.length > 0 
        ? (completedScans.reduce((sum, scan) => sum + (scan.risk_score || 0), 0) / completedScans.length).toFixed(1)
        : 'N/A';
    
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Insurance Scanner Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { text-align: center; margin-bottom: 30px; }
                .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .scan-item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .risk-critical { background-color: #f8d7da; }
                .risk-high { background-color: #fff3cd; }
                .risk-medium { background-color: #d1ecf1; }
                .risk-low { background-color: #d4edda; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f8f9fa; }
                @media print { body { margin: 0; } }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cyber Insurance Scanner Report</h1>
                <p>Generated on ${new Date().toLocaleString()}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Scans:</strong> ${totalScans}</p>
                <p><strong>Completed Scans:</strong> ${completedScans.length}</p>
                <p><strong>Average Risk Score:</strong> ${avgRiskScore}</p>
            </div>
            
            <h2>Scan Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>Vulnerabilities</th>
                        <th>Completed</th>
                    </tr>
                </thead>
                <tbody>
                    ${scans.map(scan => `
                        <tr class="risk-${scan.risk_level || 'unknown'}">
                            <td>${scan.domain || 'N/A'}</td>
                            <td>${scan.status || 'N/A'}</td>
                            <td>${scan.risk_level || 'N/A'}</td>
                            <td>${scan.risk_score || 'N/A'}</td>
                            <td>${scan.total_vulnerabilities || 0}</td>
                            <td>${scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </body>
        </html>
    `;
}

// Download blob as file
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Get timestamp for filename
function getTimestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

// Export individual scan
async function exportScan(scanId, format = 'json') {
    try {
        const response = await fetch(`/api/export/${format}/${scanId}`);
        
        if (!response.ok) {
            throw new Error(`Export failed: ${response.statusText}`);
        }
        
        const blob = await response.blob();
        const filename = `scan_${scanId}_${getTimestamp()}.${format}`;
        downloadBlob(blob, filename);
        
        showNotification(`Scan exported successfully as ${format.toUpperCase()}`, 'success');
        
    } catch (error) {
        console.error('Error exporting scan:', error);
        showNotification('Error exporting scan: ' + error.message, 'error');
    }
} 

// CSV Format Functions
function showCsvFormat() {
    const modal = `
        <div class="modal fade" id="csvFormatModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">CSV Format Specification</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <h6>Required CSV Format:</h6>
                        <div class="bg-light p-3 rounded mb-3">
                            <code>
                                domain,company_name,contact_email,priority<br/>
                                example.com,Example Corp,security@example.com,high<br/>
                                testsite.org,Test Organization,admin@testsite.org,medium<br/>
                                demo.net,Demo Company,,low
                            </code>
                        </div>
                        
                        <h6>Field Descriptions:</h6>
                        <ul>
                            <li><strong>domain</strong> (required): The domain to scan (e.g., example.com)</li>
                            <li><strong>company_name</strong> (required): Company or organization name</li>
                            <li><strong>contact_email</strong> (optional): Contact email for the organization</li>
                            <li><strong>priority</strong> (optional): Scan priority (high, medium, low)</li>
                        </ul>
                        
                        <h6>Important Notes:</h6>
                        <ul>
                            <li>Maximum 50 domains per CSV file</li>
                            <li>Domain must be valid (no http:// or www. prefix)</li>
                            <li>Company name cannot be empty</li>
                            <li>CSV must have headers in the first row</li>
                            <li>UTF-8 encoding recommended</li>
                        </ul>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="downloadCsvTemplate()">Download Template</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modal);
    const modalElement = new bootstrap.Modal(document.getElementById('csvFormatModal'));
    modalElement.show();
    
    // Clean up modal after it's hidden
    document.getElementById('csvFormatModal').addEventListener('hidden.bs.modal', function () {
        this.remove();
    });
}

function downloadCsvTemplate() {
    console.log('downloadCsvTemplate function called!');
    
    try {
        console.log('Starting CSV template download...');
        
        // Add visual feedback immediately
        const btn = document.querySelector('button[onclick="downloadCsvTemplate()"]');
        if (btn) {
            const originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Downloading...';
            btn.disabled = true;
            
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }, 2000);
        }
        
        const csvContent = `domain,company_name,contact_email,priority
example.com,Example Corporation,security@example.com,high
testsite.org,Test Organization,admin@testsite.org,medium
demo.net,Demo Company,,low
sample.biz,Sample Business,info@sample.biz,high`;

        console.log('CSV content created, length:', csvContent.length);

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        console.log('Blob created, size:', blob.size);
        
        const link = document.createElement('a');
        
        // Check if browser supports download attribute
        if (typeof link.download !== 'undefined') {
            console.log('Browser supports download attribute');
            const url = URL.createObjectURL(blob);
            console.log('Object URL created:', url);
            
            link.setAttribute('href', url);
            link.setAttribute('download', 'bulk_scan_template.csv');
            link.style.visibility = 'hidden';
            link.style.display = 'none';
            
            document.body.appendChild(link);
            console.log('Link added to document body');
            
            // Force the download
            link.click();
            console.log('Link clicked');
            
            document.body.removeChild(link);
            console.log('Link removed from document body');
            
            // Clean up the URL object
            setTimeout(() => {
                URL.revokeObjectURL(url);
                console.log('Object URL revoked');
            }, 1000);
            
            console.log('CSV template download initiated successfully');
            showAlert('success', 'CSV template download started!');
        } else {
            console.log('Browser does not support download attribute, using fallback');
            // Fallback for older browsers
            const dataUri = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvContent);
            console.log('Data URI created, length:', dataUri.length);
            
            const newWindow = window.open(dataUri, '_blank');
            if (!newWindow) {
                throw new Error('Popup blocked - please allow popups for this site');
            }
            console.log('New window opened with data URI');
            showAlert('success', 'CSV template opened in new window!');
        }
    } catch (error) {
        console.error('Error downloading CSV template:', error);
        showAlert('error', 'Failed to download CSV template: ' + error.message);
        
        // Reset button if there was an error
        const btn = document.querySelector('button[onclick="downloadCsvTemplate()"]');
        if (btn) {
            btn.innerHTML = '<i class="fas fa-download"></i> Download Template';
            btn.disabled = false;
        }
    }
}

// CSV File Validation and Processing
function validateCsvFile(input) {
    console.log('=== CSV VALIDATION STARTED ===');
    console.log('validateCsvFile called with input:', input);
    console.log('Current state:', {
        activeBulkScan: !!activeBulkScan,
        csvDataLength: csvData?.length || 0,
        timestamp: new Date().toISOString()
    });
    
    // Always reset state first
    csvData = [];
    const bulkScanBtn = document.getElementById('bulkScanBtn');
    const csvPreview = document.getElementById('csvPreview');
    
    const file = input.files[0];
    if (!file) {
        console.log('No file selected, resetting UI state');
        if (bulkScanBtn) bulkScanBtn.disabled = true;
        if (csvPreview) csvPreview.style.display = 'none';
        return;
    }

    console.log('File selected:', {
        name: file.name,
        type: file.type,
        size: file.size,
        lastModified: new Date(file.lastModified).toISOString()
    });

    // Check if a bulk scan is currently running
    if (activeBulkScan) {
        console.log('Bulk scan currently running, rejecting new upload');
        showAlert('warning', 'Cannot upload new CSV file while bulk scan is running. Please wait for completion.');
        input.value = '';
        return;
    }

    if (file.type !== 'text/csv' && !file.name.endsWith('.csv')) {
        console.log('Invalid file type:', file.type);
        showAlert('error', 'Please select a valid CSV file.');
        input.value = '';
        if (bulkScanBtn) bulkScanBtn.disabled = true;
        return;
    }

    if (file.size > 1024 * 1024) { // 1MB limit
        console.log('File too large:', file.size);
        showAlert('error', 'CSV file is too large. Maximum size is 1MB.');
        input.value = '';
        if (bulkScanBtn) bulkScanBtn.disabled = true;
        return;
    }

    console.log('File validation passed, reading content...');
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            console.log('File content read successfully, parsing...');
            parseCsvContent(e.target.result);
        } catch (error) {
            console.error('Error reading CSV file:', error);
            showAlert('error', 'Error reading CSV file: ' + error.message);
            input.value = '';
            if (bulkScanBtn) bulkScanBtn.disabled = true;
        }
    };
    reader.readAsText(file);
}

function parseCsvContent(csvContent) {
    console.log('Parsing CSV content, length:', csvContent.length);
    console.log('First 200 chars:', csvContent.substring(0, 200));
    
    const lines = csvContent.split('\n').filter(line => line.trim());
    console.log('Lines found:', lines.length);
    
    if (lines.length < 2) {
        console.log('Not enough lines in CSV');
        showAlert('error', 'CSV file must contain at least a header row and one data row.');
        document.getElementById('bulkScanBtn').disabled = true;
        return;
    }

    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/^"|"$/g, ''));
    console.log('Headers found:', headers);
    
    const requiredHeaders = ['domain', 'company_name'];
    const missingHeaders = requiredHeaders.filter(h => !headers.includes(h));
    console.log('Missing headers:', missingHeaders);

    if (missingHeaders.length > 0) {
        console.log('Required headers missing');
        showAlert('error', `Missing required headers: ${missingHeaders.join(', ')}<br/>Found headers: ${headers.join(', ')}<br/>Expected: domain, company_name, contact_email (optional), priority (optional)`);
        document.getElementById('bulkScanBtn').disabled = true;
        return;
    }

    csvData = [];
    const errors = [];

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue; // Skip empty lines
        
        const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
        console.log(`Row ${i + 1} values:`, values);
        
        if (values.length < headers.length) {
            // Allow fewer columns if optional fields are missing
            while (values.length < headers.length) {
                values.push('');
            }
        }
        
        if (values.length > headers.length) {
            errors.push(`Row ${i + 1}: Too many columns (expected ${headers.length}, got ${values.length})`);
            continue;
        }

        const row = {};
        headers.forEach((header, index) => {
            row[header] = values[index] || '';
        });

        console.log(`Row ${i + 1} parsed:`, row);

        // Validate required fields
        if (!row.domain || !row.company_name) {
            errors.push(`Row ${i + 1}: Missing required fields (domain: "${row.domain}", company_name: "${row.company_name}")`);
            continue;
        }

        // Clean and validate domain format
        const cleanDomain = row.domain.replace(/^https?:\/\//, '').replace(/^www\./, '').toLowerCase();
        console.log(`Row ${i + 1} domain validation: "${row.domain}" -> "${cleanDomain}"`);
        
        const domainValid = isValidDomain(cleanDomain);
        console.log(`Row ${i + 1} domain "${cleanDomain}" validation result: ${domainValid}`);
        
        if (!domainValid) {
            const errorMsg = `Row ${i + 1}: Invalid domain format: "${row.domain}" (cleaned: "${cleanDomain}")`;
            errors.push(errorMsg);
            console.log(`❌ ${errorMsg}`);
            continue;
        } else {
            console.log(`✅ Row ${i + 1}: Domain "${cleanDomain}" passed validation`);
        }

        csvData.push({
            domain: cleanDomain,
            company_name: row.company_name.trim(),
            contact_email: row.contact_email ? row.contact_email.trim() : '',
            priority: (row.priority || 'medium').toLowerCase()
        });
    }

    console.log('Validation results:', {
        totalRows: lines.length - 1,
        validRows: csvData.length,
        errors: errors.length
    });

    if (errors.length > 0) {
        console.log('=== CSV VALIDATION ERRORS ===');
        console.log(`Total errors: ${errors.length}`);
        console.log('All errors:', errors);
        console.log('Total rows processed:', lines.length - 1);
        console.log('Valid rows found:', csvData.length);
        
        showAlert('error', 
            `CSV validation errors (${errors.length} total):<br/>` +
            `${errors.slice(0, 5).join('<br/>')}` +
            `${errors.length > 5 ? '<br/>...and ' + (errors.length - 5) + ' more errors' : ''}<br/><br/>` +
            `Found ${csvData.length} valid rows out of ${lines.length - 1} total rows.`
        );
        document.getElementById('bulkScanBtn').disabled = true;
        return;
    }

    if (csvData.length === 0) {
        console.log('No valid rows found');
        showAlert('error', 'No valid data rows found in CSV file.');
        document.getElementById('bulkScanBtn').disabled = true;
        return;
    }

    if (csvData.length > 50) {
        console.log('Too many domains:', csvData.length);
        showAlert('error', `Too many domains. Maximum 50 allowed, found ${csvData.length}.`);
        document.getElementById('bulkScanBtn').disabled = true;
        return;
    }

    console.log('=== CSV VALIDATION SUCCESSFUL ===');
    console.log('Final csvData count:', csvData.length);
    console.log('Sample domains:', csvData.slice(0, 3).map(d => d.domain));
    console.log('All priorities:', [...new Set(csvData.map(d => d.priority))]);
    
    // Show preview and enable scan button
    try {
        showCsvPreview();
        console.log('CSV preview displayed successfully');
    } catch (error) {
        console.error('Error showing CSV preview:', error);
    }
    
    const bulkScanBtn = document.getElementById('bulkScanBtn');
    if (bulkScanBtn) {
        bulkScanBtn.disabled = false;
        console.log('✅ Bulk scan button enabled successfully');
        console.log('Button state:', {
            disabled: bulkScanBtn.disabled,
            innerHTML: bulkScanBtn.innerHTML,
            id: bulkScanBtn.id
        });
    } else {
        console.error('❌ ERROR: bulkScanBtn element not found in DOM!');
    }
    
    showAlert('success', `✅ CSV file validated successfully! Found ${csvData.length} valid domains ready for scanning.`);
}

function showCsvPreview() {
    const preview = document.getElementById('csvPreview');
    const table = document.getElementById('csvPreviewTable');
    
    let html = `
        <thead class="table-dark">
            <tr>
                <th>#</th>
                <th>Domain</th>
                <th>Company</th>
                <th>Contact Email</th>
                <th>Priority</th>
            </tr>
        </thead>
        <tbody>
    `;
    
    csvData.slice(0, 10).forEach((row, index) => {
        const priorityBadge = getPriorityBadge(row.priority);
        html += `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${row.domain}</strong></td>
                <td>${row.company_name}</td>
                <td>${row.contact_email || '<em class="text-muted">Not provided</em>'}</td>
                <td>${priorityBadge}</td>
            </tr>
        `;
    });
    
    if (csvData.length > 10) {
        html += `
            <tr>
                <td colspan="5" class="text-center text-muted">
                    ... and ${csvData.length - 10} more domains
                </td>
            </tr>
        `;
    }
    
    html += '</tbody>';
    table.innerHTML = html;
    preview.style.display = 'block';
}

function getPriorityBadge(priority) {
    const badges = {
        'high': '<span class="badge bg-danger">High</span>',
        'medium': '<span class="badge bg-warning">Medium</span>',
        'low': '<span class="badge bg-secondary">Low</span>'
    };
    return badges[priority?.toLowerCase()] || badges['medium'];
}

function isValidDomain(domain) {
    // More lenient domain validation
    if (!domain || typeof domain !== 'string') {
        console.log('Domain validation failed: empty or non-string', domain);
        return false;
    }
    
    // Clean domain for validation
    const cleanDomain = domain.trim().toLowerCase();
    
    // Check for protocols or www (should already be cleaned but double-check)
    if (cleanDomain.startsWith('http') || cleanDomain.startsWith('www.')) {
        console.log('Domain validation failed: contains protocol or www', cleanDomain);
        return false;
    }
    
    // More lenient regex that accepts most valid domain formats
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$/;
    const isValid = domainRegex.test(cleanDomain);
    
    console.log(`Domain validation for "${cleanDomain}": ${isValid}`);
    
    if (!isValid) {
        // Additional check for common patterns
        const basicCheck = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleanDomain) && 
                          !cleanDomain.startsWith('.') && 
                          !cleanDomain.endsWith('.') &&
                          !cleanDomain.includes('..') &&
                          cleanDomain.split('.').length >= 2;
        
        console.log(`Basic domain check for "${cleanDomain}": ${basicCheck}`);
        return basicCheck;
    }
    
    return isValid;
}

// Bulk Scanning Functions (Parallel Implementation)
async function startBulkScan() {
    console.log('🚀 startBulkScan() called');
    console.log('📊 csvData state:', {
        exists: !!csvData,
        type: typeof csvData,
        length: csvData ? csvData.length : 'undefined',
        isArray: Array.isArray(csvData)
    });
    
    if (!csvData || csvData.length === 0) {
        console.error('❌ No csvData available for bulk scan');
        console.error('❌ csvData:', csvData);
        console.error('❌ window.csvData:', window.csvData);
        showAlert('error', 'No valid CSV data to scan.');
        return;
    }
    
    console.log('✅ csvData validated, proceeding with bulk scan');

    const scanType = document.getElementById('bulkScanType').value;
    const concurrency = parseInt(document.getElementById('concurrencyLevel').value);
    
    // Update configuration based on user selection
    BULK_SCAN_CONFIG.maxConcurrent = concurrency;
    BULK_SCAN_CONFIG.batchSize = concurrency;
    
    const estimatedTime = csvData.length * (scanType === 'quick' ? 1.5 : 3) / (concurrency / 4); // Parallel: much faster!
    
    const confirmed = confirm(
        `Start parallel bulk scan of ${csvData.length} domains?\n\n` +
        `Scan Type: ${scanType.charAt(0).toUpperCase() + scanType.slice(1)}\n` +
        `Concurrency: ${concurrency} simultaneous scans\n` +
        `Estimated Time: ${Math.round(estimatedTime)} minutes\n\n` +
        `This will scan ${concurrency} domains in parallel. Continue?`
    );
    
    if (!confirmed) return;

    activeBulkScan = {
        domains: csvData,
        scanType: scanType,
        total: csvData.length,
        completed: 0,
        failed: 0,
        inProgress: 0,
        scanIds: [],
        failures: [],
        currentlyScanning: new Map(), // Track active scans
        startTime: Date.now(),
        progressInterval: null
    };

    updateBulkScanStatus();
    document.getElementById('bulkScanBtn').disabled = true;
    
    // Start progress monitoring
    activeBulkScan.progressInterval = setInterval(() => {
        updateBulkScanStatus();
    }, BULK_SCAN_CONFIG.progressUpdateInterval);
    
    // Start parallel scanning
    await runParallelScans();
}

async function runParallelScans() {
    const batches = createBatches(activeBulkScan.domains, BULK_SCAN_CONFIG.batchSize);
    
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        console.log(`Starting batch ${batchIndex + 1}/${batches.length} with ${batch.length} domains`);
        
        // Process batch in parallel with concurrency limit
        await processBatchWithConcurrency(batch, BULK_SCAN_CONFIG.maxConcurrent);
        
        // Short break between batches to prevent overwhelming
        if (batchIndex < batches.length - 1) {
            await sleep(200);
        }
    }
    
    // Retry failed scans if configured
    if (activeBulkScan.failures.length > 0 && BULK_SCAN_CONFIG.retryAttempts > 0) {
        await retryFailedScans();
    }
    
    finalizeBulkScan();
}

function createBatches(array, batchSize) {
    const batches = [];
    for (let i = 0; i < array.length; i += batchSize) {
        batches.push(array.slice(i, i + batchSize));
    }
    return batches;
}

async function processBatchWithConcurrency(batch, maxConcurrent) {
    const semaphore = new Array(maxConcurrent).fill(null);
    let index = 0;
    
    const scanPromises = batch.map(async (domain) => {
        // Wait for available slot
        await new Promise(resolve => {
            const checkSlot = () => {
                const freeSlot = semaphore.findIndex(slot => slot === null);
                if (freeSlot !== -1) {
                    semaphore[freeSlot] = domain;
                    resolve();
                } else {
                    setTimeout(checkSlot, 10);
                }
            };
            checkSlot();
        });
        
        try {
            await scanSingleDomain(domain);
        } finally {
            // Release slot
            const slotIndex = semaphore.findIndex(slot => slot === domain);
            if (slotIndex !== -1) {
                semaphore[slotIndex] = null;
            }
        }
    });
    
    await Promise.allSettled(scanPromises);
}

async function scanSingleDomain(domain, isRetry = false) {
    const domainKey = domain.domain;
    
    try {
        activeBulkScan.inProgress++;
        activeBulkScan.currentlyScanning.set(domainKey, {
            domain: domain.domain,
            startTime: Date.now(),
            status: 'starting'
        });
        
        updateBulkScanStatus(`Scanning ${domain.domain}...`);
        
        const response = await fetch('/api/scan/full', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                domain: domain.domain,
                company_name: domain.company_name
            })
        });

        const result = await response.json();
        
        if (result.success) {
            activeBulkScan.scanIds.push(result.data.scan_id);
            activeBulkScan.completed++;
            activeBulkScan.currentlyScanning.set(domainKey, {
                ...activeBulkScan.currentlyScanning.get(domainKey),
                status: 'completed',
                scanId: result.data.scan_id
            });
            
            if (!isRetry) {
                showAlert('success', `✅ Scan started for ${domain.domain}`, 1000);
            }
        } else {
            throw new Error(result.message || 'Unknown error');
        }
    } catch (error) {
        activeBulkScan.failed++;
        activeBulkScan.currentlyScanning.set(domainKey, {
            ...activeBulkScan.currentlyScanning.get(domainKey),
            status: 'failed',
            error: error.message
        });
        
        if (!isRetry) {
            activeBulkScan.failures.push({ domain, error: error.message, attempts: 1 });
            showAlert('warning', `❌ Failed to scan ${domain.domain}: ${error.message}`, 1500);
        }
    } finally {
        activeBulkScan.inProgress--;
        
        // Remove from currently scanning after a short delay to show completion
        setTimeout(() => {
            activeBulkScan.currentlyScanning.delete(domainKey);
        }, 1000);
    }
}

async function retryFailedScans() {
    const failedDomains = activeBulkScan.failures.filter(f => f.attempts < BULK_SCAN_CONFIG.retryAttempts);
    
    if (failedDomains.length === 0) return;
    
    console.log(`Retrying ${failedDomains.length} failed scans...`);
    updateBulkScanStatus(`Retrying ${failedDomains.length} failed scans...`);
    
    await sleep(BULK_SCAN_CONFIG.retryDelay);
    
    for (const failure of failedDomains) {
        failure.attempts++;
        activeBulkScan.failed--; // Remove from failed count for retry
        await scanSingleDomain(failure.domain, true);
        await sleep(100); // Small delay between retries
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function updateBulkScanStatus(customMessage = null) {
    const statusDiv = document.getElementById('bulkScanStatus');
    
    if (!activeBulkScan) {
        statusDiv.innerHTML = '<p class="text-muted mb-0">No bulk scan running</p>';
        return;
    }

    const { total, completed, failed, inProgress, startTime, currentlyScanning } = activeBulkScan;
    const processed = completed + failed;
    const progress = Math.round((processed / total) * 100);
    const elapsed = Math.round((Date.now() - startTime) / 1000);
    
    // Calculate rate and ETA
    const rate = processed > 0 ? processed / (elapsed / 60) : 0; // scans per minute
    const remaining = total - processed;
    const etaMinutes = rate > 0 ? Math.round(remaining / rate) : 0;

    let html = `
        <div class="mb-2">
            <div class="d-flex justify-content-between">
                <small><strong>Overall Progress</strong></small>
                <small>${processed}/${total} (${progress}%) • ${rate.toFixed(1)}/min</small>
            </div>
            <div class="progress" style="height: 10px;">
                <div class="progress-bar bg-success" style="width: ${(completed/total)*100}%" title="Completed"></div>
                <div class="progress-bar bg-warning" style="width: ${(inProgress/total)*100}%" title="In Progress"></div>
                <div class="progress-bar bg-danger" style="width: ${(failed/total)*100}%" title="Failed"></div>
            </div>
        </div>
        
        <div class="row text-center mb-2">
            <div class="col-3">
                <div class="text-success"><strong>${completed}</strong></div>
                <small>Completed</small>
            </div>
            <div class="col-3">
                <div class="text-warning"><strong>${inProgress}</strong></div>
                <small>In Progress</small>
            </div>
            <div class="col-3">
                <div class="text-danger"><strong>${failed}</strong></div>
                <small>Failed</small>
            </div>
            <div class="col-3">
                <div class="text-primary"><strong>${Math.floor(elapsed / 60)}m ${elapsed % 60}s</strong></div>
                <small>Elapsed ${etaMinutes > 0 ? `• ~${etaMinutes}m left` : ''}</small>
            </div>
        </div>
    `;

    // Show currently scanning domains
    if (currentlyScanning && currentlyScanning.size > 0) {
        html += '<div class="mb-2"><small><strong>Currently Scanning:</strong></small><div class="mt-1">';
        
        let count = 0;
        for (const [domain, info] of currentlyScanning) {
            if (count >= 6) { // Show max 6 active scans
                html += `<small class="text-muted">...and ${currentlyScanning.size - 6} more</small>`;
                break;
            }
            
            const statusIcon = {
                'starting': '🟡',
                'completed': '✅', 
                'failed': '❌'
            }[info.status] || '🔄';
            
            const duration = Math.round((Date.now() - info.startTime) / 1000);
            html += `<small class="badge bg-light text-dark me-1 mb-1">${statusIcon} ${domain} (${duration}s)</small>`;
            count++;
        }
        html += '</div></div>';
    }

    if (customMessage) {
        html += `<div class="mt-2"><small class="text-info"><strong>${customMessage}</strong></small></div>`;
    }

    statusDiv.innerHTML = html;
}

function finalizeBulkScan() {
    if (!activeBulkScan) return;
    
    const { completed, failed, total, startTime, progressInterval, scanIds } = activeBulkScan;
    const elapsed = Math.round((Date.now() - startTime) / 1000);
    const rate = completed > 0 ? (completed / (elapsed / 60)).toFixed(1) : '0';
    
    // Clear progress monitoring
    if (progressInterval) {
        clearInterval(progressInterval);
    }
    
    // Show completion summary
    const successRate = Math.round((completed / total) * 100);
    showAlert('success', 
        `🎉 Parallel bulk scan completed!<br/>` +
        `✅ ${completed} scans started successfully (${successRate}%)<br/>` +
        `❌ ${failed} scans failed<br/>` +
        `⚡ Total: ${total} domains processed in ${Math.floor(elapsed / 60)}m ${elapsed % 60}s<br/>` +
        `📊 Average rate: ${rate} scans/minute<br/>` +
        `🔗 ${scanIds.length} scan IDs generated`
    );
    
    // Final status update
    updateBulkScanStatus('Scan completed! Refreshing dashboard...');
    
    // Refresh the dashboard to show new scans
    setTimeout(() => {
        loadDashboardData();
        refreshAllScans();
    }, 1500);
    
    // COMPLETE CLEANUP AND RESET FOR NEXT BULK SCAN
    setTimeout(() => {
        console.log('Finalizing bulk scan and resetting state for next upload...');
        resetBulkScanState();
        console.log('🎉 Ready for next bulk scan upload!');
    }, 2000);
    
    console.log(`Bulk scan completed: ${completed}/${total} successful, rate: ${rate}/min`);
}

// ==============================================
// APOLLO.IO INTEGRATION FUNCTIONS
// ==============================================

// Simplified CSV parser specifically for Apollo data
function parseApolloCSV(csvContent) {
    console.log('🔍 Parsing Apollo CSV...');
    
    try {
        const lines = csvContent.split('\n').filter(line => line.trim());
        console.log('📄 CSV lines found:', lines.length);
        
        if (lines.length < 2) {
            console.error('❌ Not enough lines in Apollo CSV');
            return [];
        }
        
        // Parse header
        const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/^"|"$/g, ''));
        console.log('📋 Headers:', headers);
        
        // Check for required columns
        if (!headers.includes('domain') || !headers.includes('company_name')) {
            console.error('❌ Missing required headers. Found:', headers);
            return [];
        }
        
        const parsedData = [];
        const errors = [];
        
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
            
            // Create row object
            const row = {};
            headers.forEach((header, index) => {
                row[header] = values[index] || '';
            });
            
            // Validate required fields
            if (!row.domain || !row.company_name) {
                errors.push(`Row ${i + 1}: Missing domain or company_name`);
                continue;
            }
            
            // Clean domain
            const cleanDomain = row.domain
                .replace(/^https?:\/\//, '')
                .replace(/^www\./, '')
                .toLowerCase()
                .trim();
            
            // Basic domain validation (more lenient than the main function)
            if (!cleanDomain || cleanDomain.length < 3 || !cleanDomain.includes('.')) {
                errors.push(`Row ${i + 1}: Invalid domain "${row.domain}"`);
                continue;
            }
            
            parsedData.push({
                domain: cleanDomain,
                company_name: row.company_name.trim(),
                contact_email: row.contact_email ? row.contact_email.trim() : '',
                priority: (row.priority || 'medium').toLowerCase()
            });
        }
        
        console.log('✅ Apollo CSV parsing results:');
        console.log(`   Total rows: ${lines.length - 1}`);
        console.log(`   Valid domains: ${parsedData.length}`);
        console.log(`   Errors: ${errors.length}`);
        
        if (errors.length > 0) {
            console.warn('⚠️ Apollo CSV parsing errors:', errors.slice(0, 5));
        }
        
        if (parsedData.length > 0) {
            console.log('📋 Sample parsed domains:', parsedData.slice(0, 3).map(d => d.domain));
        }
        
        return parsedData;
        
    } catch (error) {
        console.error('❌ Apollo CSV parsing error:', error);
        return [];
    }
}

// Upload Apollo.io CSV file
async function uploadApolloFile(input) {
    console.log('🚀 Apollo file upload initiated');
    
    if (!input.files || !input.files[0]) {
        console.log('❌ No file selected');
        return;
    }
    
    const file = input.files[0];
    console.log('📁 File selected:', file.name, 'Size:', file.size);
    
    // Validate file type
    if (!file.name.toLowerCase().endsWith('.csv')) {
        showAlert('error', 'Please select a CSV file');
        input.value = '';
        return;
    }
    
    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
        showAlert('error', 'File size too large. Maximum 10MB allowed.');
        input.value = '';
        return;
    }
    
    try {
        // Update status to show uploading
        updateApolloStatus('uploading', 'Uploading and parsing Apollo.io data...');
        
        // Create FormData for upload
        const formData = new FormData();
        formData.append('file', file);
        
        console.log('📤 Uploading Apollo file...');
        
        // Upload to backend
        const response = await fetch('/api/apollo/upload', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Upload failed: ${response.status} - ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ Apollo upload result:', result);
        
        if (result.success) {
            // Store the data (fixing the response structure)
            apolloData = result.data.companies || [];
            // The scanner format would need to be fetched separately, but for now use the companies data
            apolloScannerFormat = result.data.companies ? result.data.companies.map(company => ({
                domain: company.domain,
                company_name: company.company_name,
                priority: company.priority || 'medium'
            })) : [];
            
            // Update UI with success
            updateApolloStatus('success', result.message);
            
            // Enable buttons
            enableApolloButtons(true);
            
            // Show preview if we have data
            if (apolloData && apolloData.length > 0) {
                updateApolloPreview(apolloData); // Show the companies
            }
            
            showAlert('success', `Apollo data processed! ${result.data.total_companies} companies loaded.`);
            
        } else {
            throw new Error(result.error || 'Upload failed');
        }
        
    } catch (error) {
        console.error('❌ Apollo upload error:', error);
        updateApolloStatus('error', `Error: ${error.message}`);
        showAlert('error', `Apollo upload failed: ${error.message}`);
        
        // Reset file input
        input.value = '';
        enableApolloButtons(false);
    }
}

// Start Apollo bulk scan
async function startApolloScan() {
    console.log('🚀 Starting Apollo bulk scan');
    
    if (!apolloData || apolloData.length === 0) {
        showAlert('error', 'No Apollo data available. Please upload a file first.');
        return;
    }
    
    try {
        // Get scan settings
        const scanType = document.getElementById('apolloScanType').value;
        const concurrency = parseInt(document.getElementById('apolloConcurrency').value);
        
        console.log('📋 Apollo scan settings:', { scanType, concurrency, domains: apolloData.length });
        
        // Load the scanner format data from the API
        updateApolloStatus('scanning', 'Loading scanner format data...');
        
        const response = await fetch('/api/apollo/scanner-data');
        if (!response.ok) {
            throw new Error('Failed to load Apollo scanner format data');
        }
        
        const result = await response.json();
        console.log('📄 Apollo scanner data loaded:', result);
        
        if (!result.success) {
            throw new Error(result.error || 'Failed to load Apollo scanner data');
        }
        
        // Use the data directly from the API response
        const apolloParsedData = result.data.companies;
        
        if (!apolloParsedData || apolloParsedData.length === 0) {
            console.error('❌ Apollo data loading failed - no valid domains found');
            throw new Error('No valid domains found in Apollo scanner data');
        }
        
        // Set the global csvData for bulk scanning (both ways to ensure compatibility)
        window.csvData = apolloParsedData;
        csvData = apolloParsedData; // Also set the local variable
        console.log('✅ Apollo data loaded successfully:', apolloParsedData.length, 'domains');
        console.log('✅ Set csvData variables:', {
            windowCsvData: !!window.csvData,
            localCsvData: !!csvData,
            length: apolloParsedData.length
        });
        
        console.log('📊 Loaded Apollo scanner data:', window.csvData.length, 'domains');
        console.log('📋 Sample domains:', window.csvData.slice(0, 3).map(d => d.domain));
        
        // The global csvData variable is already set by parseCsvContent
        
        // Update bulk scan config for Apollo
        BULK_SCAN_CONFIG.maxConcurrent = concurrency;
        BULK_SCAN_CONFIG.batchSize = concurrency;
        
        // Set the bulk scan type
        document.getElementById('bulkScanType').value = scanType;
        document.getElementById('concurrencyLevel').value = concurrency.toString();
        
        // Update Apollo status
        updateApolloStatus('scanning', `Starting bulk scan of ${window.csvData.length} domains...`);
        
        // Debug before calling startBulkScan
        console.log('🎯 About to call startBulkScan() from Apollo');
        console.log('🎯 csvData before startBulkScan:', {
            windowCsvData: !!window.csvData,
            localCsvData: !!csvData,
            globalLength: window.csvData ? window.csvData.length : 'undefined',
            localLength: csvData ? csvData.length : 'undefined'
        });
        
        // Start the actual bulk scan using existing system
        console.log('🎯 Calling startBulkScan()...');
        await startBulkScan();
        console.log('🎯 startBulkScan() completed');
        
        showAlert('info', `Apollo bulk scan started! Scanning ${window.csvData.length} domains with ${concurrency} parallel workers.`);
        
    } catch (error) {
        console.error('❌ Apollo scan error:', error);
        updateApolloStatus('error', `Scan failed: ${error.message}`);
        showAlert('error', `Failed to start Apollo scan: ${error.message}`);
    }
}

// Show Apollo data preview
function showApolloPreview() {
    console.log('👁️ Showing Apollo preview');
    
    const previewDiv = document.getElementById('apolloPreview');
    
    if (!apolloData || apolloData.length === 0) {
        showAlert('warning', 'No Apollo data to preview. Upload a file first.');
        return;
    }
    
    // Toggle preview visibility
    if (previewDiv.style.display === 'none') {
        updateApolloPreview(apolloData);
        previewDiv.style.display = 'block';
        document.getElementById('apolloPreviewBtn').innerHTML = '<i class="fas fa-eye-slash"></i> Hide Preview';
    } else {
        previewDiv.style.display = 'none';
        document.getElementById('apolloPreviewBtn').innerHTML = '<i class="fas fa-eye"></i> Preview Data';
    }
}

// Reset Apollo data
function resetApolloData() {
    console.log('🗑️ Resetting Apollo data');
    
    // Clear data
    apolloData = null;
    apolloScannerFormat = null;
    
    // Reset file input
    const fileInput = document.getElementById('apolloCsvFile');
    if (fileInput) {
        fileInput.value = '';
    }
    
    // Hide preview
    const previewDiv = document.getElementById('apolloPreview');
    if (previewDiv) {
        previewDiv.style.display = 'none';
    }
    
    // Disable buttons
    enableApolloButtons(false);
    
    // Reset status
    updateApolloStatus('ready', 'No Apollo data uploaded. Upload your Apollo.io CSV export to get started.');
    
    showAlert('info', 'Apollo data cleared.');
}

// Update Apollo status display
function updateApolloStatus(type, message) {
    const statusDiv = document.getElementById('apolloStatus');
    if (!statusDiv) return;
    
    let alertClass = 'alert-info';
    let icon = 'fas fa-info-circle';
    
    switch (type) {
        case 'uploading':
            alertClass = 'alert-warning';
            icon = 'fas fa-spinner fa-spin';
            break;
        case 'success':
            alertClass = 'alert-success';
            icon = 'fas fa-check-circle';
            break;
        case 'error':
            alertClass = 'alert-danger';
            icon = 'fas fa-exclamation-circle';
            break;
        case 'scanning':
            alertClass = 'alert-primary';
            icon = 'fas fa-search fa-spin';
            break;
        case 'ready':
        default:
            alertClass = 'alert-info';
            icon = 'fas fa-info-circle';
            break;
    }
    
    statusDiv.innerHTML = `
        <div class="alert ${alertClass}">
            <i class="${icon}"></i> ${message}
        </div>
    `;
}

// Enable/disable Apollo buttons
function enableApolloButtons(enabled) {
    const buttons = ['apolloScanBtn', 'apolloPreviewBtn', 'apolloResetBtn'];
    
    buttons.forEach(buttonId => {
        const button = document.getElementById(buttonId);
        if (button) {
            button.disabled = !enabled;
        }
    });
}

// Update Apollo preview table
function updateApolloPreview(data) {
    const table = document.getElementById('apolloPreviewTable');
    if (!table || !data || data.length === 0) return;
    
    const maxRows = Math.min(data.length, 10); // Show max 10 rows
    const sample = data.slice(0, maxRows);
    
    // Get all unique keys from the data
    const allKeys = new Set();
    sample.forEach(row => {
        Object.keys(row).forEach(key => allKeys.add(key));
    });
    
    const keys = Array.from(allKeys);
    
    let html = `
        <thead class="table-dark">
            <tr>
                ${keys.map(key => `<th>${escapeHtml(key)}</th>`).join('')}
            </tr>
        </thead>
        <tbody>
    `;
    
    sample.forEach(row => {
        html += '<tr>';
        keys.forEach(key => {
            const value = row[key] || '';
            const displayValue = value.toString().length > 50 
                ? value.toString().substring(0, 50) + '...' 
                : value.toString();
            html += `<td>${escapeHtml(displayValue)}</td>`;
        });
        html += '</tr>';
    });
    
    html += '</tbody>';
    
    if (data.length > maxRows) {
        html += `
            <tfoot>
                <tr>
                    <td colspan="${keys.length}" class="text-center text-muted">
                        Showing ${maxRows} of ${data.length} companies
                    </td>
                </tr>
            </tfoot>
        `;
    }
    
    table.innerHTML = html;
} 

// Domain Summary Functions
async function loadDomainSummary() {
    try {
        console.log('Loading domain summary...');
        
        const response = await fetch('/api/analytics/domain-summary');
        const data = await response.json();
        
        if (data.success) {
            displayDomainSummary(data.data);
        } else {
            throw new Error(data.error || 'Failed to load domain summary');
        }
    } catch (error) {
        console.error('Error loading domain summary:', error);
        displayDomainSummaryError(error.message);
    }
}

function displayDomainSummary(summary) {
    const container = document.getElementById('domainSummary');
    
    if (!summary || summary.total_domains === 0) {
        container.innerHTML = '<p class="text-muted">No domain data available. Start scanning domains to see the security summary.</p>';
        return;
    }
    
    // Calculate percentages
    const cleanPercentage = summary.total_domains > 0 ? ((summary.clean_domains / summary.total_domains) * 100).toFixed(1) : 0;
    const vulnerablePercentage = summary.total_domains > 0 ? ((summary.vulnerable_domains / summary.total_domains) * 100).toFixed(1) : 0;
    
    let html = `
        <!-- Summary Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card border-primary h-100">
                    <div class="card-body text-center">
                        <i class="fas fa-globe fa-2x text-primary mb-2"></i>
                        <h4 class="card-title text-primary">${summary.total_domains}</h4>
                        <p class="card-text">Total Domains</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-success h-100">
                    <div class="card-body text-center">
                        <i class="fas fa-shield-alt fa-2x text-success mb-2"></i>
                        <h4 class="card-title text-success">${summary.clean_domains}</h4>
                        <p class="card-text">Clean Domains</p>
                        <small class="text-muted">${cleanPercentage}%</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-warning h-100">
                    <div class="card-body text-center">
                        <i class="fas fa-exclamation-triangle fa-2x text-warning mb-2"></i>
                        <h4 class="card-title text-warning">${summary.vulnerable_domains}</h4>
                        <p class="card-text">Vulnerable Domains</p>
                        <small class="text-muted">${vulnerablePercentage}%</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card border-info h-100">
                    <div class="card-body text-center">
                        <i class="fas fa-bug fa-2x text-info mb-2"></i>
                        <h4 class="card-title text-info">${summary.total_vulnerabilities}</h4>
                        <p class="card-text">Total Vulnerabilities</p>
                        <small class="text-muted">Avg: ${summary.average_vulnerabilities_per_domain}</small>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Severity breakdown
    if (summary.total_vulnerabilities > 0) {
        html += `
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0"><i class="fas fa-chart-bar"></i> Vulnerability Severity Distribution</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="badge bg-danger fs-6 mb-2">${summary.severity_breakdown.CRITICAL || 0}</div>
                                        <div class="text-muted">Critical</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="badge bg-warning fs-6 mb-2">${summary.severity_breakdown.HIGH || 0}</div>
                                        <div class="text-muted">High</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="badge bg-info fs-6 mb-2">${summary.severity_breakdown.MEDIUM || 0}</div>
                                        <div class="text-muted">Medium</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="badge bg-secondary fs-6 mb-2">${summary.severity_breakdown.LOW || 0}</div>
                                        <div class="text-muted">Low</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Clean domains section
    if (summary.clean_domains > 0) {
        html += `
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card border-success">
                        <div class="card-header bg-success text-white">
                            <h5 class="mb-0"><i class="fas fa-check-circle"></i> Clean Domains (${summary.clean_domains})</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
        `;
        
        summary.clean_domain_list.forEach(domain => {
            html += `
                <div class="col-md-4 mb-3">
                    <div class="card bg-light">
                        <div class="card-body">
                            <h6 class="card-title text-success">
                                <i class="fas fa-shield-alt"></i> ${escapeHtml(domain.domain)}
                            </h6>
                            <p class="card-text text-muted">${escapeHtml(domain.company_name)}</p>
                            <div class="d-flex justify-content-between align-items-center">
                                <small class="text-success">
                                    <i class="fas fa-check"></i> No vulnerabilities
                                </small>
                                <a href="/scan/${domain.scan_id}" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-eye"></i> View
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += `
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Vulnerable domains section
    if (summary.vulnerable_domains > 0) {
        html += `
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card border-warning">
                        <div class="card-header bg-warning text-dark">
                            <h5 class="mb-0"><i class="fas fa-exclamation-triangle"></i> Vulnerable Domains (${summary.vulnerable_domains})</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
        `;
        
        summary.vulnerable_domain_list.forEach(domain => {
            const riskClass = getRiskBadgeClass(domain.risk_category);
            html += `
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start">
                                <div>
                                    <h6 class="card-title text-warning">
                                        <i class="fas fa-exclamation-triangle"></i> ${escapeHtml(domain.domain)}
                                    </h6>
                                    <p class="card-text text-muted">${escapeHtml(domain.company_name)}</p>
                                </div>
                                <span class="badge ${riskClass}">${domain.risk_category.toUpperCase()}</span>
                            </div>
                            
                            <div class="row text-center mt-3">
                                <div class="col-3">
                                    <div class="text-danger">
                                        <strong>${domain.severity_breakdown.CRITICAL || 0}</strong>
                                        <small class="d-block text-muted">Critical</small>
                                    </div>
                                </div>
                                <div class="col-3">
                                    <div class="text-warning">
                                        <strong>${domain.severity_breakdown.HIGH || 0}</strong>
                                        <small class="d-block text-muted">High</small>
                                    </div>
                                </div>
                                <div class="col-3">
                                    <div class="text-info">
                                        <strong>${domain.severity_breakdown.MEDIUM || 0}</strong>
                                        <small class="d-block text-muted">Medium</small>
                                    </div>
                                </div>
                                <div class="col-3">
                                    <div class="text-secondary">
                                        <strong>${domain.severity_breakdown.LOW || 0}</strong>
                                        <small class="d-block text-muted">Low</small>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="d-flex justify-content-between align-items-center mt-3">
                                <small class="text-muted">
                                    Total: ${domain.vulnerability_count} vulnerabilities
                                </small>
                                <a href="/scan/${domain.scan_id}" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-eye"></i> View Details
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += `
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Risk highlights
    if (summary.highest_risk_domain || summary.lowest_risk_domain) {
        html += `
            <div class="row">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0"><i class="fas fa-chart-line"></i> Risk Highlights</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
        `;
        
        if (summary.highest_risk_domain) {
            const highestRiskClass = getRiskBadgeClass(summary.highest_risk_domain.risk_category);
            html += `
                <div class="col-md-6">
                    <div class="card border-danger">
                        <div class="card-body">
                            <h6 class="card-title text-danger">
                                <i class="fas fa-exclamation-triangle"></i> Highest Risk Domain
                            </h6>
                            <p class="card-text">
                                <strong>${escapeHtml(summary.highest_risk_domain.domain)}</strong><br>
                                ${escapeHtml(summary.highest_risk_domain.company_name)}
                            </p>
                            <div class="d-flex justify-content-between align-items-center">
                                <span class="badge ${highestRiskClass}">
                                    ${summary.highest_risk_domain.risk_score}/100
                                </span>
                                <small class="text-muted">
                                    ${summary.highest_risk_domain.vulnerability_count} vulnerabilities
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        if (summary.lowest_risk_domain) {
            const lowestRiskClass = getRiskBadgeClass(summary.lowest_risk_domain.risk_category);
            html += `
                <div class="col-md-6">
                    <div class="card border-success">
                        <div class="card-body">
                            <h6 class="card-title text-success">
                                <i class="fas fa-shield-alt"></i> Lowest Risk Domain
                            </h6>
                            <p class="card-text">
                                <strong>${escapeHtml(summary.lowest_risk_domain.domain)}</strong><br>
                                ${escapeHtml(summary.lowest_risk_domain.company_name)}
                            </p>
                            <div class="d-flex justify-content-between align-items-center">
                                <span class="badge ${lowestRiskClass}">
                                    ${summary.lowest_risk_domain.risk_score}/100
                                </span>
                                <small class="text-muted">
                                    ${summary.lowest_risk_domain.vulnerability_count} vulnerabilities
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        html += `
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

function displayDomainSummaryError(errorMessage) {
    const container = document.getElementById('domainSummary');
    container.innerHTML = `
        <div class="alert alert-warning" role="alert">
            <i class="fas fa-exclamation-triangle"></i>
            <strong>Error loading domain summary:</strong> ${escapeHtml(errorMessage)}
        </div>
    `;
}

async function refreshDomainSummary() {
    console.log('Refreshing domain summary...');
    
    // Show loading state
    const container = document.getElementById('domainSummary');
    container.innerHTML = '<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading domain summary...</div>';
    
    // Load fresh data
    await loadDomainSummary();
}