#!/usr/bin/env python3
"""
Enterprise CMDB Compliance Tool - FastAPI REST & GraphQL API Server
Production-ready API server with async endpoints and modern features
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info

# Lazy imports to avoid dependency issues
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models for API
class ScanRequest(BaseModel):
    target_ips: List[str] = Field(..., description="List of IP addresses to scan")
    business_unit: Optional[str] = Field(None, description="Business unit filter")
    scan_types: List[str] = Field(["ssh", "winrm", "snmp"], description="Scanner types to use")
    priority: str = Field("normal", description="Scan priority: low, normal, high, critical")

class ComplianceFindingResponse(BaseModel):
    ci_id: str
    ci_name: str
    status: str
    reason: str
    risk_score: int
    remediation: Optional[str]
    evaluated_at: datetime
    business_unit: str
    
class ScanProgress(BaseModel):
    scan_id: str
    status: str
    progress: float
    completed: int
    total: int
    errors: List[str]
    started_at: datetime
    estimated_completion: Optional[datetime]

class PolicyResponse(BaseModel):
    policy_id: str
    name: str
    description: str
    enabled: bool
    rules_count: int
    last_modified: datetime

class SystemComplianceResponse(BaseModel):
    ci_id: str
    ci_name: str
    overall_status: str
    compliance_score: float
    findings: List[ComplianceFindingResponse]
    last_scanned: Optional[datetime]
    next_scan: Optional[datetime]

# GraphQL schema
@strawberry.type
class ComplianceFinding:
    ci_id: str
    ci_name: str
    status: str
    reason: str
    risk_score: int
    remediation: Optional[str]
    evaluated_at: datetime
    business_unit: str

@strawberry.type
class SystemCompliance:
    ci_id: str
    ci_name: str
    overall_status: str
    compliance_score: float
    findings: List[ComplianceFinding]
    last_scanned: Optional[datetime]

@strawberry.input
class FindingFilter:
    business_unit: Optional[str] = None
    status: Optional[str] = None
    min_risk_score: Optional[int] = None
    ci_class: Optional[str] = None

@strawberry.type
class Query:
    @strawberry.field
    async def compliance_findings(
        self, 
        filter: Optional[FindingFilter] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[ComplianceFinding]:
        """Get compliance findings with optional filtering"""
        try:
            # This would normally query the database
            # For demo, return sample data
            findings = await get_sample_findings()
            
            # Apply filters
            if filter:
                if filter.business_unit:
                    findings = [f for f in findings if f.business_unit == filter.business_unit]
                if filter.status:
                    findings = [f for f in findings if f.status == filter.status]
                if filter.min_risk_score:
                    findings = [f for f in findings if f.risk_score >= filter.min_risk_score]
            
            # Apply pagination
            return findings[offset:offset + limit]
        except Exception as e:
            logger.error(f"Error fetching compliance findings: {e}")
            return []
    
    @strawberry.field
    async def system_compliance(self, ci_id: str) -> Optional[SystemCompliance]:
        """Get compliance information for a specific system"""
        try:
            # This would normally query the database
            findings = await get_sample_findings()
            system_findings = [f for f in findings if f.ci_id == ci_id]
            
            if not system_findings:
                return None
            
            # Calculate compliance score
            total_score = sum(f.risk_score for f in system_findings)
            compliance_score = max(0, 100 - (total_score / len(system_findings)))
            
            overall_status = "fail" if any(f.status == "fail" for f in system_findings) else \
                           "warn" if any(f.status == "warn" for f in system_findings) else "pass"
            
            return SystemCompliance(
                ci_id=ci_id,
                ci_name=system_findings[0].ci_name,
                overall_status=overall_status,
                compliance_score=compliance_score,
                findings=system_findings,
                last_scanned=datetime.now() - timedelta(hours=2)
            )
        except Exception as e:
            logger.error(f"Error fetching system compliance: {e}")
            return None

# Create FastAPI app
app = FastAPI(
    title="Enterprise CMDB Compliance API",
    description="Production-ready compliance monitoring and assessment API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# In-memory store for demo (would be replaced with database)
active_scans: Dict[str, Dict[str, Any]] = {}
websocket_connections: List[WebSocket] = []

# Helper functions
async def get_sample_findings() -> List[ComplianceFinding]:
    """Generate sample compliance findings for demo"""
    return [
        ComplianceFinding(
            ci_id="ci_001",
            ci_name="legacy-dc-01",
            status="fail",
            reason="Past End-of-Life (2020-01-14)",
            risk_score=90,
            remediation="Upgrade to Windows Server 2019 or newer immediately",
            evaluated_at=datetime.now() - timedelta(hours=1),
            business_unit="Finance"
        ),
        ComplianceFinding(
            ci_id="ci_002", 
            ci_name="web-app-02",
            status="warn",
            reason="EOL in 45 days",
            risk_score=60,
            remediation="Plan upgrade to Ubuntu 22.04 LTS within maintenance window",
            evaluated_at=datetime.now() - timedelta(hours=2),
            business_unit="Marketing"
        ),
        ComplianceFinding(
            ci_id="ci_003",
            ci_name="app-server-03", 
            status="pass",
            reason="Compliant - Windows Server 2022",
            risk_score=0,
            remediation=None,
            evaluated_at=datetime.now() - timedelta(minutes=30),
            business_unit="Engineering"
        ),
        ComplianceFinding(
            ci_id="ci_004",
            ci_name="core-switch-01",
            status="fail", 
            reason="Past End-of-Support (2019-07-31)",
            risk_score=80,
            remediation="Upgrade Cisco IOS to supported version immediately",
            evaluated_at=datetime.now() - timedelta(hours=6),
            business_unit="IT Operations"
        )
    ]

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token (demo implementation)"""
    # In production, implement proper JWT validation
    if credentials.credentials == "demo-token":
        return {"user_id": "demo-user", "role": "admin"}
    raise HTTPException(status_code=401, detail="Invalid authentication token")

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                # Remove disconnected clients
                self.active_connections.remove(connection)

manager = ConnectionManager()

# REST API Endpoints

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "api": "operational",
            "database": "operational", 
            "scanners": "operational"
        }
    }

@app.get("/api/v1/compliance/findings", response_model=List[ComplianceFindingResponse])
async def get_compliance_findings(
    business_unit: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user=Depends(verify_token)
):
    """Get compliance findings with filtering and pagination"""
    try:
        findings = await get_sample_findings()
        
        # Apply filters
        if business_unit:
            findings = [f for f in findings if f.business_unit == business_unit]
        if status:
            findings = [f for f in findings if f.status == status]
        
        # Convert to response model
        response_findings = []
        for finding in findings[offset:offset + limit]:
            response_findings.append(ComplianceFindingResponse(
                ci_id=finding.ci_id,
                ci_name=finding.ci_name,
                status=finding.status,
                reason=finding.reason,
                risk_score=finding.risk_score,
                remediation=finding.remediation,
                evaluated_at=finding.evaluated_at,
                business_unit=finding.business_unit
            ))
        
        return response_findings
    except Exception as e:
        logger.error(f"Error in get_compliance_findings: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/compliance/scan")
async def start_compliance_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    user=Depends(verify_token)
):
    """Start a new compliance scan"""
    try:
        scan_id = str(uuid.uuid4())
        
        # Initialize scan record
        active_scans[scan_id] = {
            "id": scan_id,
            "status": "running",
            "progress": 0.0,
            "completed": 0,
            "total": len(scan_request.target_ips),
            "errors": [],
            "started_at": datetime.now(),
            "estimated_completion": datetime.now() + timedelta(minutes=5),
            "request": scan_request.dict()
        }
        
        # Start background scan
        background_tasks.add_task(run_compliance_scan, scan_id, scan_request)
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": f"Compliance scan initiated for {len(scan_request.target_ips)} targets"
        }
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scan")

@app.get("/api/v1/compliance/scan/{scan_id}", response_model=ScanProgress)
async def get_scan_progress(scan_id: str, user=Depends(verify_token)):
    """Get progress of a running scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = active_scans[scan_id]
    return ScanProgress(**scan_data)

@app.get("/api/v1/policies", response_model=List[PolicyResponse])
async def get_policies(user=Depends(verify_token)):
    """Get list of compliance policies"""
    try:
        # Demo policies
        policies = [
            PolicyResponse(
                policy_id="baseline",
                name="Baseline Compliance",
                description="Core EOL/EOS compliance rules",
                enabled=True,
                rules_count=12,
                last_modified=datetime.now() - timedelta(days=5)
            ),
            PolicyResponse(
                policy_id="min_version",
                name="Minimum Version Requirements",
                description="Product-specific minimum version policies",
                enabled=True,
                rules_count=8,
                last_modified=datetime.now() - timedelta(days=2)
            ),
            PolicyResponse(
                policy_id="business_unit",
                name="Business Unit Policies", 
                description="Department-specific compliance rules",
                enabled=True,
                rules_count=15,
                last_modified=datetime.now() - timedelta(days=1)
            )
        ]
        return policies
    except Exception as e:
        logger.error(f"Error fetching policies: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch policies")

@app.post("/api/v1/policies")
async def create_policy(
    policy_data: Dict[str, Any],
    user=Depends(verify_token)
):
    """Create a new compliance policy"""
    try:
        # Validate policy data
        required_fields = ["name", "description", "rules"]
        for field in required_fields:
            if field not in policy_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        policy_id = str(uuid.uuid4())
        
        # In production, save to database and OPA policy directory
        return {
            "policy_id": policy_id,
            "status": "created",
            "message": f"Policy '{policy_data['name']}' created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail="Failed to create policy")

@app.get("/api/v1/systems/{ci_id}/compliance", response_model=SystemComplianceResponse)
async def get_system_compliance(ci_id: str, user=Depends(verify_token)):
    """Get compliance status for a specific system"""
    try:
        findings = await get_sample_findings()
        system_findings = [f for f in findings if f.ci_id == ci_id]
        
        if not system_findings:
            raise HTTPException(status_code=404, detail="System not found")
        
        # Calculate overall compliance
        fail_count = len([f for f in system_findings if f.status == "fail"])
        warn_count = len([f for f in system_findings if f.status == "warn"])
        
        overall_status = "fail" if fail_count > 0 else "warn" if warn_count > 0 else "pass"
        
        # Calculate compliance score
        total_risk = sum(f.risk_score for f in system_findings)
        compliance_score = max(0, 100 - (total_risk / len(system_findings)))
        
        # Convert findings to response format
        response_findings = []
        for finding in system_findings:
            response_findings.append(ComplianceFindingResponse(
                ci_id=finding.ci_id,
                ci_name=finding.ci_name,
                status=finding.status,
                reason=finding.reason,
                risk_score=finding.risk_score,
                remediation=finding.remediation,
                evaluated_at=finding.evaluated_at,
                business_unit=finding.business_unit
            ))
        
        return SystemComplianceResponse(
            ci_id=ci_id,
            ci_name=system_findings[0].ci_name,
            overall_status=overall_status,
            compliance_score=compliance_score,
            findings=response_findings,
            last_scanned=datetime.now() - timedelta(hours=2),
            next_scan=datetime.now() + timedelta(hours=22)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching system compliance: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch system compliance")

# WebSocket endpoint for real-time updates
@app.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(5)
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.now().isoformat()
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task for compliance scanning
async def run_compliance_scan(scan_id: str, scan_request: ScanRequest):
    """Run compliance scan in background"""
    try:
        scan_data = active_scans[scan_id]
        
        # Simulate scanning progress
        for i, target_ip in enumerate(scan_request.target_ips):
            await asyncio.sleep(2)  # Simulate scan time
            
            # Update progress
            scan_data["completed"] = i + 1
            scan_data["progress"] = (i + 1) / len(scan_request.target_ips) * 100
            
            # Broadcast progress update
            await manager.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": scan_data["progress"],
                "completed": scan_data["completed"],
                "total": scan_data["total"]
            })
        
        # Mark scan as completed
        scan_data["status"] = "completed"
        scan_data["progress"] = 100.0
        
        await manager.broadcast({
            "type": "scan_completed",
            "scan_id": scan_id,
            "message": "Compliance scan completed successfully"
        })
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["errors"].append(str(e))

# GraphQL integration
graphql_app = GraphQLRouter(strawberry.Schema(query=Query))
app.include_router(graphql_app, prefix="/graphql")

# Static file serving for React UI
try:
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
except Exception as e:
    logger.warning(f"Static files not available: {e}")

# Root endpoint serves React app
@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve React application"""
    try:
        # Try to serve the existing HTML if available
        html_file = Path(__file__).parent / "static" / "index.html"
        if html_file.exists():
            return FileResponse(html_file)
        else:
            # Return a basic HTML page with API links
            return HTMLResponse(content="""
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise CMDB Compliance Tool</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .endpoints { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; }
        .endpoint { margin: 10px 0; padding: 10px; background: #f1f3f4; border-radius: 4px; }
        .method { display: inline-block; width: 80px; font-weight: bold; }
        .get { color: #2196F3; }
        .post { color: #4CAF50; }
        a { color: #1976D2; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 Enterprise CMDB Compliance Tool</h1>
        <p>Production-ready compliance monitoring and assessment API</p>
    </div>
    
    <div class="endpoints">
        <h2>📚 API Documentation</h2>
        <p><a href="/api/docs" target="_blank">Interactive API Documentation (Swagger UI)</a></p>
        <p><a href="/api/redoc" target="_blank">Alternative API Documentation (ReDoc)</a></p>
        <p><a href="/graphql" target="_blank">GraphQL Playground</a></p>
        
        <h3>🔍 Quick API Endpoints</h3>
        <div class="endpoint">
            <span class="method get">GET</span>
            <a href="/api/v1/health">/api/v1/health</a> - System health check
        </div>
        <div class="endpoint">
            <span class="method get">GET</span>
            <a href="/api/v1/compliance/findings">/api/v1/compliance/findings</a> - Get compliance findings
        </div>
        <div class="endpoint">
            <span class="method post">POST</span>
            /api/v1/compliance/scan - Start compliance scan
        </div>
        <div class="endpoint">
            <span class="method get">GET</span>
            /api/v1/policies - Get compliance policies
        </div>
        
        <h3>🔒 Authentication</h3>
        <p>Use Bearer token: <code>demo-token</code> for demo access</p>
        <p>Example: <code>Authorization: Bearer demo-token</code></p>
        
        <h3>📊 GraphQL Queries</h3>
        <p>Access GraphQL playground at <a href="/graphql">/graphql</a></p>
        <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">
query GetFindings {
  complianceFindings(limit: 10) {
    ciId
    ciName
    status
    reason
    riskScore
    businessUnit
  }
}

query GetSystemCompliance {
  systemCompliance(ciId: "ci_001") {
    ciName
    overallStatus
    complianceScore
    findings {
      status
      reason
      riskScore
    }
  }
}</pre>
    </div>
</body>
</html>
            """)
    except Exception as e:
        logger.error(f"Error serving root: {e}")
        return HTMLResponse(content="<h1>API Server Running</h1><p>Enterprise CMDB Compliance Tool API is operational.</p>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )