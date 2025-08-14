// ServiceNow CMDB Compliance Scanner - Frontend Application

class ComplianceApp {
    constructor() {
        this.currentScanId = null;
        this.scanInterval = null;
        this.init();
    }

    init() {
        this.bindEventListeners();
        this.checkHealth();
        this.loadRecentScans();
    }

    bindEventListeners() {
        // Scan form submission
        const scanForm = document.getElementById('scanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startScan();
            });
        }

        // Health check button
        const healthBtn = document.getElementById('healthCheckBtn');
        if (healthBtn) {
            healthBtn.addEventListener('click', () => this.checkHealth());
        }

        // Quick actions
        const quickDemo = document.getElementById('quickDemo');
        if (quickDemo) {
            quickDemo.addEventListener('click', () => this.runQuickDemo());
        }

        const viewScans = document.getElementById('viewScans');
        if (viewScans) {
            viewScans.addEventListener('click', () => this.viewAllScans());
        }

        // Export buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('export-btn')) {
                const scanId = e.target.dataset.scanId;
                this.exportResults(scanId);
            }
        });
    }

    async checkHealth() {
        const healthContainer = document.getElementById('healthStatus');
        const healthBtn = document.getElementById('healthCheckBtn');

        try {
            this.showLoading(healthBtn);
            const response = await fetch('/api/health');
            const health = await response.json();

            this.displayHealthStatus(health, healthContainer);
        } catch (error) {
            this.showError('Health check failed: ' + error.message, healthContainer);
        } finally {
            this.hideLoading(healthBtn);
        }
    }

    displayHealthStatus(health, container) {
        const statusClass = health.status === 'healthy' ? 'health-healthy' : 
                           health.status === 'degraded' ? 'health-degraded' : 'health-unhealthy';

        const serviceNowIcon = health.servicenow ? '✅' : '❌';
        const openAiIcon = health.openai ? '✅' : '❌';

        container.innerHTML = `
            <div class="alert alert-${health.status === 'healthy' ? 'success' : 'warning'} fade-in">
                <div>
                    <strong>System Status: ${health.status.toUpperCase()}</strong>
                    <div style="margin-top: 0.5rem;">
                        <div class="health-status ${statusClass}">
                            ${serviceNowIcon} ServiceNow CMDB Connection
                        </div>
                        <div class="health-status ${statusClass}">
                            ${openAiIcon} OpenAI API (CrewAI)
                        </div>
                    </div>
                    <small style="color: var(--gray-600);">Last checked: ${new Date().toLocaleTimeString()}</small>
                </div>
            </div>
        `;
    }

    async startScan() {
        const form = document.getElementById('scanForm');
        const formData = new FormData(form);
        
        const scanRequest = {
            scope: formData.get('scope'),
            mode: formData.get('mode'),
            max_threads: parseInt(formData.get('maxThreads'))
        };

        const submitBtn = document.getElementById('startScanBtn');
        const statusContainer = document.getElementById('scanStatus');

        try {
            this.showLoading(submitBtn, 'Starting scan...');
            
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanRequest)
            });

            const result = await response.json();

            if (response.ok) {
                this.currentScanId = result.scan_id;
                this.showSuccess(`Scan started successfully! ID: ${result.scan_id}`, statusContainer);
                this.startPolling(result.scan_id);
                this.disableForm(true);
            } else {
                this.showError('Failed to start scan: ' + result.detail, statusContainer);
            }
        } catch (error) {
            this.showError('Error starting scan: ' + error.message, statusContainer);
        } finally {
            this.hideLoading(submitBtn, 'Start Scan');
        }
    }

    startPolling(scanId) {
        // Clear any existing interval
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
        }

        this.scanInterval = setInterval(async () => {
            await this.updateScanStatus(scanId);
        }, 2000);

        // Also update immediately
        this.updateScanStatus(scanId);
    }

    async updateScanStatus(scanId) {
        try {
            const response = await fetch(`/api/scan/status/${scanId}`);
            const status = await response.json();

            this.displayScanProgress(status);

            if (status.status === 'completed' || status.status === 'failed') {
                clearInterval(this.scanInterval);
                this.disableForm(false);
                
                if (status.status === 'completed' && status.results) {
                    this.displayResults(status.results);
                }
            }
        } catch (error) {
            console.error('Error polling scan status:', error);
        }
    }

    displayScanProgress(status) {
        const progressContainer = document.getElementById('progressContainer');
        
        let progressClass = 'info';
        if (status.status === 'completed') progressClass = 'success';
        if (status.status === 'failed') progressClass = 'error';

        progressContainer.innerHTML = `
            <div class="card slide-up">
                <h3>Scan Progress</h3>
                <div class="alert alert-${progressClass}">
                    <div>
                        <strong>Scan ${status.scan_id}</strong><br>
                        Status: ${status.status.toUpperCase()}<br>
                        ${status.message}
                    </div>
                </div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${status.progress}%"></div>
                    </div>
                    <div class="progress-text">${status.progress}% Complete</div>
                </div>
                <small style="color: var(--gray-600);">
                    Started: ${new Date(status.start_time).toLocaleString()}
                </small>
                ${status.status === 'completed' ? `
                    <button class="btn btn-success export-btn" data-scan-id="${status.scan_id}" style="margin-top: 1rem;">
                        📥 Download Results
                    </button>
                ` : ''}
            </div>
        `;
    }

    displayResults(results) {
        const resultsContainer = document.getElementById('resultsContainer');
        
        if (results.summary_statistics) {
            const stats = results.summary_statistics;
            const complianceScore = results.compliance_score || 0;

            resultsContainer.innerHTML = `
                <div class="card fade-in">
                    <h3>📊 Compliance Results</h3>
                    
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <span class="metric-value">${stats.total_systems}</span>
                            <div class="metric-label">Total Systems</div>
                        </div>
                        <div class="metric-card metric-success">
                            <span class="metric-value">${stats.compliant}</span>
                            <div class="metric-label">Compliant</div>
                        </div>
                        <div class="metric-card metric-critical">
                            <span class="metric-value">${stats.non_compliant}</span>
                            <div class="metric-label">Non-Compliant</div>
                        </div>
                        <div class="metric-card metric-warning">
                            <span class="metric-value">${stats.critical_violations}</span>
                            <div class="metric-label">Critical Issues</div>
                        </div>
                    </div>

                    <div class="alert alert-info">
                        <div>
                            <strong>Overall Compliance Score: ${complianceScore}%</strong><br>
                            <small>EOL Systems: ${stats.eol_systems || 0} | EOS Systems: ${stats.eos_systems || 0}</small>
                        </div>
                    </div>

                    ${this.generateResultsTable(results.detailed_results || [])}
                </div>
            `;
        } else {
            resultsContainer.innerHTML = `
                <div class="card fade-in">
                    <h3>📊 Scan Results</h3>
                    <div class="alert alert-info">
                        <div>Scan completed successfully. Results format varies by scan mode.</div>
                    </div>
                </div>
            `;
        }
    }

    generateResultsTable(detailedResults) {
        if (!detailedResults || detailedResults.length === 0) {
            return '<p style="color: var(--gray-600); text-align: center; margin: 2rem 0;">No detailed results available.</p>';
        }

        const rows = detailedResults.slice(0, 10).map(result => {
            const complianceClass = result.compliance_status ? 
                result.compliance_status.toLowerCase().replace('_', '-') : 'unknown';
            
            return `
                <tr>
                    <td><strong>${result.ci_name || 'Unknown'}</strong></td>
                    <td>${result.ip_address || 'N/A'}</td>
                    <td>${result.os_name || 'Unknown'} ${result.os_version || ''}</td>
                    <td>
                        <span class="badge badge-${complianceClass}">
                            ${result.compliance_status || 'Unknown'}
                        </span>
                    </td>
                    <td>
                        <span style="color: ${result.risk_score >= 70 ? 'var(--danger-color)' : 
                                             result.risk_score >= 40 ? 'var(--warning-color)' : 
                                             'var(--success-color)'};">
                            ${result.risk_score || 0}
                        </span>
                    </td>
                    <td>${(result.violations || []).filter(v => v.severity === 'CRITICAL').length}</td>
                </tr>
            `;
        }).join('');

        return `
            <table class="results-table">
                <thead>
                    <tr>
                        <th>System Name</th>
                        <th>IP Address</th>
                        <th>Operating System</th>
                        <th>Compliance Status</th>
                        <th>Risk Score</th>
                        <th>Critical Issues</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
            ${detailedResults.length > 10 ? 
                `<p style="text-align: center; color: var(--gray-600); margin-top: 1rem;">
                    Showing first 10 of ${detailedResults.length} results. Download full report for complete data.
                </p>` : ''
            }
        `;
    }

    async runQuickDemo() {
        // Set form to demo mode and trigger scan
        document.getElementById('mode').value = 'demo';
        document.getElementById('scope').value = 'all';
        await this.startScan();
    }

    async viewAllScans() {
        try {
            const response = await fetch('/api/scans');
            const data = await response.json();
            
            this.displayScanHistory(data);
        } catch (error) {
            this.showError('Failed to load scan history: ' + error.message);
        }
    }

    displayScanHistory(data) {
        const modal = this.createModal('Scan History', this.generateScanHistoryContent(data));
        document.body.appendChild(modal);
    }

    generateScanHistoryContent(data) {
        const activeScans = Object.entries(data.active_scans || {});
        const completedScans = data.completed_scans || [];

        return `
            <div style="max-height: 60vh; overflow-y: auto;">
                <h4>Active Scans (${activeScans.length})</h4>
                ${activeScans.length === 0 ? '<p>No active scans</p>' : 
                  activeScans.map(([id, scan]) => `
                    <div class="alert alert-info" style="margin: 0.5rem 0;">
                        <strong>${id}</strong> - ${scan.status} (${scan.progress}%)
                    </div>
                  `).join('')
                }
                
                <h4 style="margin-top: 2rem;">Completed Scans (${completedScans.length})</h4>
                ${completedScans.length === 0 ? '<p>No completed scans</p>' :
                  completedScans.slice(-10).map(scanId => `
                    <div class="alert alert-success" style="margin: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;">
                        <span><strong>${scanId}</strong></span>
                        <button class="btn btn-sm btn-secondary export-btn" data-scan-id="${scanId}">
                            Download
                        </button>
                    </div>
                  `).join('')
                }
            </div>
        `;
    }

    async exportResults(scanId) {
        try {
            const response = await fetch(`/api/scan/download/${scanId}`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `compliance_scan_results_${scanId}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                this.showSuccess('Results downloaded successfully!');
            } else {
                this.showError('Failed to download results');
            }
        } catch (error) {
            this.showError('Export failed: ' + error.message);
        }
    }

    async loadRecentScans() {
        try {
            const response = await fetch('/api/scans');
            const data = await response.json();
            
            const recentContainer = document.getElementById('recentScans');
            if (recentContainer && data.completed_scans) {
                const recent = data.completed_scans.slice(-3);
                if (recent.length > 0) {
                    recentContainer.innerHTML = `
                        <h4>Recent Scans</h4>
                        ${recent.map(scanId => `
                            <div class="alert alert-info" style="margin: 0.5rem 0; display: flex; justify-content: space-between; align-items: center;">
                                <span>${scanId}</span>
                                <button class="btn btn-sm btn-secondary export-btn" data-scan-id="${scanId}">
                                    📥 Download
                                </button>
                            </div>
                        `).join('')}
                    `;
                }
            }
        } catch (error) {
            console.error('Failed to load recent scans:', error);
        }
    }

    disableForm(disabled) {
        const form = document.getElementById('scanForm');
        const inputs = form.querySelectorAll('input, select, button');
        inputs.forEach(input => {
            input.disabled = disabled;
        });
    }

    createModal(title, content) {
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.5); z-index: 1000;
            display: flex; align-items: center; justify-content: center;
            padding: 2rem;
        `;
        
        modal.innerHTML = `
            <div class="card" style="max-width: 800px; width: 100%; max-height: 80vh; overflow-y: auto;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3>${title}</h3>
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">✕</button>
                </div>
                ${content}
            </div>
        `;
        
        modal.className = 'modal';
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
        
        return modal;
    }

    showLoading(element, text = 'Loading...') {
        element.disabled = true;
        element.innerHTML = `<span class="spinner"></span> ${text}`;
    }

    hideLoading(element, originalText) {
        element.disabled = false;
        element.innerHTML = originalText;
    }

    showSuccess(message, container = null) {
        this.showMessage(message, 'success', container);
    }

    showError(message, container = null) {
        this.showMessage(message, 'error', container);
    }

    showMessage(message, type, container = null) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} fade-in`;
        alert.innerHTML = `<div>${message}</div>`;
        
        if (container) {
            container.innerHTML = '';
            container.appendChild(alert);
        } else {
            document.body.appendChild(alert);
            setTimeout(() => alert.remove(), 5000);
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new ComplianceApp();
});