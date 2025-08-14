#!/usr/bin/env python3
"""
ServiceNow CMDB Compliance Scanner - Web Interface
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
import os
import json
import asyncio
from datetime import datetime
from typing import Optional, Dict, List
from crew import ComplianceScanningCrew
from servicenow_connector import ServiceNowConnector
from network_scanner import NetworkOSScanner
from compliance_analyzer import ComplianceAnalyzer

app = FastAPI(title="ServiceNow CMDB Compliance Scanner", version="1.0.0")

# Global state for tracking scans
active_scans = {}
scan_results = {}

class ScanRequest(BaseModel):
    scope: str = "all"
    mode: str = "standalone"  # standalone, crewai, demo
    max_threads: int = 5

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
    start_time: str
    results: Optional[Dict] = None

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Main dashboard"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ServiceNow CMDB Compliance Scanner</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 40px; }
            .header h1 { color: #333; margin-bottom: 10px; }
            .header p { color: #666; font-size: 18px; }
            .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            .section h2 { color: #444; margin-top: 0; }
            .button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; font-size: 16px; }
            .button:hover { background: #0056b3; }
            .button.secondary { background: #6c757d; }
            .button.success { background: #28a745; }
            .button.warning { background: #ffc107; color: #333; }
            .status { padding: 15px; border-radius: 4px; margin: 10px 0; }
            .status.success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .status.error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .status.info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
            .form-group { margin: 15px 0; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
            .form-group select, .form-group input { width: 200px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
            .results { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; }
            .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 10px 15px; background: #e9ecef; border-radius: 4px; }
            .metric .value { font-size: 24px; font-weight: bold; color: #007bff; }
            .metric .label { font-size: 12px; color: #666; }
        </style>
        <script>
            async function startScan() {
                const scope = document.getElementById('scope').value;
                const mode = document.getElementById('mode').value;
                const maxThreads = document.getElementById('maxThreads').value;
                
                try {
                    const response = await fetch('/api/scan/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scope, mode, max_threads: parseInt(maxThreads) })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        document.getElementById('status').innerHTML = 
                            `<div class="status info">Scan started with ID: ${result.scan_id}</div>`;
                        pollScanStatus(result.scan_id);
                    } else {
                        document.getElementById('status').innerHTML = 
                            `<div class="status error">Error: ${result.detail}</div>`;
                    }
                } catch (error) {
                    document.getElementById('status').innerHTML = 
                        `<div class="status error">Error: ${error.message}</div>`;
                }
            }
            
            async function pollScanStatus(scanId) {
                const interval = setInterval(async () => {
                    try {
                        const response = await fetch(`/api/scan/status/${scanId}`);
                        const status = await response.json();
                        
                        document.getElementById('status').innerHTML = 
                            `<div class="status info">
                                <strong>Scan ${scanId}</strong><br>
                                Status: ${status.status}<br>
                                Progress: ${status.progress}%<br>
                                Message: ${status.message}
                            </div>`;
                        
                        if (status.status === 'completed' || status.status === 'failed') {
                            clearInterval(interval);
                            if (status.results) {
                                displayResults(status.results);
                            }
                        }
                    } catch (error) {
                        clearInterval(interval);
                        document.getElementById('status').innerHTML = 
                            `<div class="status error">Error polling status: ${error.message}</div>`;
                    }
                }, 2000);
            }
            
            function displayResults(results) {
                let html = '<div class="results"><h3>Scan Results</h3>';
                
                if (results.summary_statistics) {
                    const stats = results.summary_statistics;
                    html += `
                        <div class="metric">
                            <div class="value">${stats.total_systems}</div>
                            <div class="label">Total Systems</div>
                        </div>
                        <div class="metric">
                            <div class="value">${stats.compliant}</div>
                            <div class="label">Compliant</div>
                        </div>
                        <div class="metric">
                            <div class="value">${stats.non_compliant}</div>
                            <div class="label">Non-Compliant</div>
                        </div>
                        <div class="metric">
                            <div class="value">${stats.critical_violations}</div>
                            <div class="label">Critical Issues</div>
                        </div>
                    `;
                }
                
                html += '</div>';
                document.getElementById('results').innerHTML = html;
            }
            
            async function checkHealth() {
                try {
                    const response = await fetch('/api/health');
                    const health = await response.json();
                    
                    let html = '<div class="status ';
                    html += health.status === 'healthy' ? 'success' : 'error';
                    html += `"><strong>System Health: ${health.status}</strong><br>`;
                    html += `ServiceNow: ${health.servicenow ? '✅' : '❌'}<br>`;
                    html += `OpenAI: ${health.openai ? '✅' : '❌'}</div>`;
                    
                    document.getElementById('health').innerHTML = html;
                } catch (error) {
                    document.getElementById('health').innerHTML = 
                        `<div class="status error">Health check failed: ${error.message}</div>`;
                }
            }
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 ServiceNow CMDB Compliance Scanner</h1>
                <p>Multi-Agent Network OS Compliance Analysis</p>
            </div>
            
            <div class="section">
                <h2>System Health</h2>
                <button class="button" onclick="checkHealth()">Check Health</button>
                <div id="health"></div>
            </div>
            
            <div class="section">
                <h2>Start Compliance Scan</h2>
                <div class="form-group">
                    <label for="scope">Scope:</label>
                    <select id="scope">
                        <option value="all">All Systems</option>
                        <option value="servers">Servers Only</option>
                        <option value="network">Network Devices</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="mode">Mode:</label>
                    <select id="mode">
                        <option value="demo">Demo (Sample Data)</option>
                        <option value="standalone">Standalone (Direct)</option>
                        <option value="crewai">CrewAI (Full Workflow)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="maxThreads">Max Threads:</label>
                    <input type="number" id="maxThreads" value="5" min="1" max="20">
                </div>
                
                <button class="button" onclick="startScan()">Start Scan</button>
            </div>
            
            <div class="section">
                <h2>Scan Status</h2>
                <div id="status">No active scans</div>
            </div>
            
            <div class="section">
                <h2>Results</h2>
                <div id="results">No results yet</div>
            </div>
            
            <div class="section">
                <h2>Quick Actions</h2>
                <button class="button secondary" onclick="window.open('/api/scans', '_blank')">View All Scans</button>
                <button class="button secondary" onclick="window.open('/docs', '_blank')">API Documentation</button>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/api/health")
async def health_check():
    """Check system health and dependencies"""
    health = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "servicenow": False,
        "openai": False,
        "dependencies": {}
    }
    
    # Check ServiceNow connection
    try:
        connector = ServiceNowConnector()
        health["servicenow"] = True
    except:
        health["servicenow"] = False
        health["status"] = "degraded"
    
    # Check OpenAI API
    health["openai"] = bool(os.getenv('OPENAI_API_KEY'))
    if not health["openai"]:
        health["status"] = "degraded"
    
    return health

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a compliance scan"""
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]  # Unique ID
    
    # Initialize scan status
    active_scans[scan_id] = {
        "status": "starting",
        "progress": 0,
        "message": "Initializing scan...",
        "start_time": datetime.now().isoformat(),
        "request": request.dict()
    }
    
    # Start background task
    background_tasks.add_task(execute_scan, scan_id, request)
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    status = active_scans[scan_id].copy()
    
    # Add results if completed
    if scan_id in scan_results:
        status["results"] = scan_results[scan_id]
    
    return status

@app.get("/api/scans")
async def list_scans():
    """List all scans"""
    return {
        "active_scans": active_scans,
        "completed_scans": list(scan_results.keys())
    }

async def execute_scan(scan_id: str, request: ScanRequest):
    """Execute scan in background"""
    try:
        # Update status
        active_scans[scan_id].update({
            "status": "running",
            "progress": 10,
            "message": "Starting scan execution..."
        })
        
        if request.mode == "demo":
            # Demo mode with sample data
            active_scans[scan_id].update({
                "progress": 50,
                "message": "Running compliance analysis demo..."
            })
            
            analyzer = ComplianceAnalyzer()
            demo_cis = [
                {
                    'ci_name': 'legacy-server-01',
                    'ip_address': '10.1.1.10',
                    'detected_os': 'Windows Server 2008 R2',
                    'detected_version': '2008 R2'
                },
                {
                    'ci_name': 'web-server-02',
                    'ip_address': '10.1.1.20',
                    'detected_os': 'Ubuntu',
                    'detected_version': '16.04'
                },
                {
                    'ci_name': 'app-server-03',
                    'ip_address': '10.1.1.30',
                    'detected_os': 'Windows Server 2019',
                    'detected_version': '2019'
                }
            ]
            
            results = analyzer.analyze_ci_list(demo_cis)
            
        elif request.mode == "standalone":
            # Standalone mode
            active_scans[scan_id].update({
                "progress": 20,
                "message": "Connecting to ServiceNow..."
            })
            
            # ServiceNow extraction
            connector = ServiceNowConnector()
            cis = connector.get_network_elements()
            
            active_scans[scan_id].update({
                "progress": 40,
                "message": f"Scanning {len(cis)} CIs..."
            })
            
            # Network scanning (limited for web interface)
            scanner = NetworkOSScanner(max_threads=min(request.max_threads, 3))
            sample_cis = cis[:10] if len(cis) > 10 else cis  # Limit for web demo
            scan_results_data = scanner.scan_ci_list(sample_cis)
            
            active_scans[scan_id].update({
                "progress": 70,
                "message": "Analyzing compliance..."
            })
            
            # Compliance analysis
            analyzer = ComplianceAnalyzer()
            results = analyzer.analyze_ci_list(scan_results_data)
            
        elif request.mode == "crewai":
            # CrewAI workflow
            active_scans[scan_id].update({
                "progress": 30,
                "message": "Executing CrewAI workflow..."
            })
            
            crew = ComplianceScanningCrew()
            crewai_result = crew.run_compliance_scan(request.scope)
            
            if crewai_result['success']:
                results = crewai_result
            else:
                raise Exception(f"CrewAI workflow failed: {crewai_result.get('error', 'Unknown error')}")
        
        # Complete scan
        active_scans[scan_id].update({
            "status": "completed",
            "progress": 100,
            "message": "Scan completed successfully"
        })
        
        scan_results[scan_id] = results
        
    except Exception as e:
        active_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "message": f"Scan failed: {str(e)}"
        })

@app.get("/api/scan/download/{scan_id}")
async def download_results(scan_id: str):
    """Download scan results as JSON"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Results not found")
    
    filename = f"compliance_scan_results_{scan_id}.json"
    
    with open(filename, 'w') as f:
        json.dump(scan_results[scan_id], f, indent=2, default=str)
    
    return FileResponse(filename, filename=filename)

if __name__ == "__main__":
    print("🌐 Starting ServiceNow CMDB Compliance Scanner Web Interface")
    print("📊 Dashboard: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)