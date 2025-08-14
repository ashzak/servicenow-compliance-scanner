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
from compliance_analyzer import ComplianceAnalyzer

# Lazy imports to avoid dependency issues
ComplianceScanningCrew = None
ServiceNowConnector = None
NetworkOSScanner = None

app = FastAPI(title="ServiceNow CMDB Compliance Scanner", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

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
    """Main dashboard with modern UI"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ServiceNow CMDB Compliance Scanner</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/static/css/styles.css">
    </head>
    <body>
        <div class="container">
            <!-- Header Section -->
            <div class="header">
                <h1><span class="emoji">🔍</span>ServiceNow CMDB Compliance Scanner</h1>
                <p>Multi-Agent Network OS Compliance Analysis Platform</p>
            </div>

            <!-- Main Grid Layout -->
            <div class="grid">
                <!-- System Health Card -->
                <div class="card">
                    <h2>🏥 System Health</h2>
                    <button id="healthCheckBtn" class="btn btn-primary">Check Health Status</button>
                    <div id="healthStatus"></div>
                </div>

                <!-- Quick Actions Card -->
                <div class="card">
                    <h2>⚡ Quick Actions</h2>
                    <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                        <button id="quickDemo" class="btn btn-success btn-large">🧪 Run Demo Scan</button>
                        <button id="viewScans" class="btn btn-secondary">📋 View Scan History</button>
                        <a href="/docs" target="_blank" class="btn btn-secondary">📚 API Documentation</a>
                    </div>
                    <div id="recentScans" style="margin-top: 1rem;"></div>
                </div>

                <!-- Scan Configuration Card -->
                <div class="card grid-full">
                    <h2>🎯 Configure Compliance Scan</h2>
                    <form id="scanForm">
                        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                            <div class="form-group">
                                <label for="scope">📊 Scan Scope</label>
                                <select id="scope" name="scope" class="form-control">
                                    <option value="all">🌐 All Systems</option>
                                    <option value="servers">🖥️ Servers Only</option>
                                    <option value="network">🔗 Network Devices</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="mode">🚀 Execution Mode</label>
                                <select id="mode" name="mode" class="form-control">
                                    <option value="demo">🧪 Demo (Sample Data)</option>
                                    <option value="standalone">⚡ Standalone (Direct)</option>
                                    <option value="crewai">🤖 CrewAI (AI Workflow)</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="maxThreads">⚙️ Max Threads</label>
                                <input type="number" id="maxThreads" name="maxThreads" 
                                       class="form-control" value="5" min="1" max="20">
                            </div>
                            
                            <div class="form-group" style="display: flex; align-items: end;">
                                <button type="submit" id="startScanBtn" class="btn btn-primary btn-large" style="width: 100%;">
                                    🚀 Start Compliance Scan
                                </button>
                            </div>
                        </div>
                    </form>
                </div>

                <!-- Scan Progress Card -->
                <div id="progressContainer" class="grid-full">
                    <!-- Progress will be dynamically inserted here -->
                </div>

                <!-- Scan Status Card -->
                <div class="card">
                    <h2>📊 Scan Status</h2>
                    <div id="scanStatus">
                        <div class="alert alert-info">
                            <div>No active scans. Configure and start a scan to begin compliance analysis.</div>
                        </div>
                    </div>
                </div>

                <!-- Results Card -->
                <div id="resultsContainer" class="grid-full">
                    <!-- Results will be dynamically inserted here -->
                </div>
            </div>

            <!-- Footer -->
            <div style="text-align: center; margin-top: 3rem; padding: 2rem; color: var(--gray-600);">
                <p>ServiceNow CMDB Compliance Scanner | Multi-Agent CrewAI System</p>
                <p style="font-size: 0.875rem;">Real-time OS compliance monitoring and risk assessment</p>
            </div>
        </div>

        <script src="/static/js/app.js"></script>
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
        global ServiceNowConnector
        if ServiceNowConnector is None:
            from servicenow_connector import ServiceNowConnector
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
            global ServiceNowConnector, NetworkOSScanner
            if ServiceNowConnector is None:
                from servicenow_connector import ServiceNowConnector
            if NetworkOSScanner is None:
                from network_scanner import NetworkOSScanner
                
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
            
            global ComplianceScanningCrew
            if ComplianceScanningCrew is None:
                from crew import ComplianceScanningCrew
                
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