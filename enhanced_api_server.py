#!/usr/bin/env python3
"""
Enhanced Enterprise CMDB Compliance Tool - FastAPI with Real OpenAI Integration
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import uuid

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field
from pathlib import Path

# Import our LLM assistant with real OpenAI integration
try:
    from llm_assistant import ComplianceAssistant
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models
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

class AIQuestionRequest(BaseModel):
    question: str = Field(..., description="Question to ask the AI assistant")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context for the question")

class AIResponse(BaseModel):
    question: str
    answer: str
    sources: List[str]
    timestamp: str
    context_used: bool

# Create FastAPI app
app = FastAPI(
    title="Enterprise CMDB Compliance API with AI",
    description="Production-ready compliance monitoring with real AI assistance",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize AI Assistant with real OpenAI
ai_assistant = None

@app.on_event("startup")
async def startup_event():
    """Initialize AI assistant on startup"""
    global ai_assistant
    
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and LLM_AVAILABLE:
        config = {
            "llm": {
                "provider": "openai",
                "model": "gpt-3.5-turbo",
                "api_key": openai_key,
                "max_tokens": 1000,
                "temperature": 0.1
            },
            "embeddings": {
                "model": "all-MiniLM-L6-v2"
            },
            "vector_db": {
                "path": "./compliance_chroma_db"
            }
        }
        
        try:
            ai_assistant = ComplianceAssistant(config)
            logger.info("✅ AI Assistant initialized with real OpenAI API")
        except Exception as e:
            logger.error(f"Failed to initialize AI assistant: {e}")
            ai_assistant = None
    else:
        logger.warning("❌ OpenAI API key not found or LLM assistant not available")

# In-memory store for demo
active_scans: Dict[str, Dict[str, Any]] = {}

# Sample data functions
async def get_sample_findings() -> List[ComplianceFindingResponse]:
    """Generate sample compliance findings"""
    return [
        ComplianceFindingResponse(
            ci_id="ci_001",
            ci_name="legacy-dc-01",
            status="fail",
            reason="Past End-of-Life (2020-01-14)",
            risk_score=90,
            remediation="Upgrade to Windows Server 2019 or newer immediately",
            evaluated_at=datetime.now() - timedelta(hours=1),
            business_unit="Finance"
        ),
        ComplianceFindingResponse(
            ci_id="ci_002", 
            ci_name="web-app-02",
            status="warn",
            reason="EOL in 45 days",
            risk_score=60,
            remediation="Plan upgrade to Ubuntu 22.04 LTS within maintenance window",
            evaluated_at=datetime.now() - timedelta(hours=2),
            business_unit="Marketing"
        ),
        ComplianceFindingResponse(
            ci_id="ci_003",
            ci_name="app-server-03", 
            status="pass",
            reason="Compliant - Windows Server 2022",
            risk_score=0,
            remediation=None,
            evaluated_at=datetime.now() - timedelta(minutes=30),
            business_unit="Engineering"
        ),
        ComplianceFindingResponse(
            ci_id="ci_004",
            ci_name="core-switch-01",
            status="fail", 
            reason="Past End-of-Support (2019-07-31)",
            risk_score=80,
            remediation="Upgrade Cisco IOS to supported version immediately",
            evaluated_at=datetime.now() - timedelta(hours=6),
            business_unit="IT Operations"
        ),
        ComplianceFindingResponse(
            ci_id="ci_005",
            ci_name="db-server-prod",
            status="fail",
            reason="Critical vulnerability CVE-2023-12345 - Known exploited",
            risk_score=95,
            remediation="Apply security patch immediately - system in CISA KEV catalog",
            evaluated_at=datetime.now() - timedelta(minutes=15),
            business_unit="Engineering"
        )
    ]

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections[:]:
            try:
                await connection.send_json(message)
            except:
                self.active_connections.remove(connection)

manager = ConnectionManager()

# API Endpoints

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "api": "operational",
            "ai_assistant": "operational" if ai_assistant else "unavailable",
            "database": "operational", 
            "scanners": "operational"
        },
        "ai_status": {
            "enabled": ai_assistant is not None,
            "provider": "openai" if ai_assistant else None,
            "model": "gpt-3.5-turbo" if ai_assistant else None
        }
    }

@app.get("/api/v1/compliance/findings", response_model=List[ComplianceFindingResponse])
async def get_compliance_findings(
    business_unit: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get compliance findings with filtering and pagination"""
    try:
        findings = await get_sample_findings()
        
        # Apply filters
        if business_unit:
            findings = [f for f in findings if f.business_unit == business_unit]
        if status:
            findings = [f for f in findings if f.status == status]
        
        return findings[offset:offset + limit]
    except Exception as e:
        logger.error(f"Error in get_compliance_findings: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/compliance/scan")
async def start_compliance_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Start a new compliance scan"""
    try:
        scan_id = str(uuid.uuid4())
        
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
        
        background_tasks.add_task(run_compliance_scan, scan_id, scan_request)
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": f"Compliance scan initiated for {len(scan_request.target_ips)} targets"
        }
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scan")

@app.post("/api/v1/assistant/ask", response_model=AIResponse)
async def ask_ai_assistant(request: AIQuestionRequest):
    """Ask the AI compliance assistant a question with real OpenAI integration"""
    try:
        if ai_assistant:
            # Use real AI assistant with OpenAI
            logger.info(f"🤖 Processing AI question: {request.question}")
            
            # Add current compliance context
            findings = await get_sample_findings()
            context = {
                "findings": [f.dict() for f in findings],
                "systems_count": len(findings),
                "last_scan": datetime.now().isoformat(),
                "compliance_summary": {
                    "total": len(findings),
                    "compliant": len([f for f in findings if f.status == "pass"]),
                    "warnings": len([f for f in findings if f.status == "warn"]),
                    "critical": len([f for f in findings if f.status == "fail"])
                }
            }
            
            # Merge with any additional context from request
            if request.context:
                context.update(request.context)
            
            result = await ai_assistant.ask_question(request.question, context)
            
            return AIResponse(
                question=result["question"],
                answer=result["answer"],
                sources=result["sources"],
                timestamp=result["timestamp"],
                context_used=result.get("context_used", True)
            )
        else:
            # Fallback to rule-based responses
            logger.warning("🤖 Using fallback AI (OpenAI not configured)")
            answer = generate_simple_answer(request.question)
            
            return AIResponse(
                question=request.question,
                answer=answer,
                sources=["Built-in compliance knowledge base"],
                timestamp=datetime.now().isoformat(),
                context_used=False
            )
            
    except Exception as e:
        logger.error(f"Error processing AI question: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process question: {str(e)}")

@app.post("/api/v1/assistant/analyze")
async def analyze_compliance_with_ai():
    """Get AI analysis of current compliance posture"""
    try:
        if ai_assistant:
            findings = await get_sample_findings()
            findings_dict = [f.dict() for f in findings]
            
            logger.info("🤖 Generating AI compliance analysis")
            analysis = await ai_assistant.analyze_compliance_findings(findings_dict)
            
            return {
                "analysis": analysis,
                "generated_by": "real_ai",
                "model": "gpt-3.5-turbo",
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Simple analysis without AI
            findings = await get_sample_findings()
            
            total = len(findings)
            critical = len([f for f in findings if f.status == "fail"])
            warnings = len([f for f in findings if f.status == "warn"])
            compliant = len([f for f in findings if f.status == "pass"])
            
            return {
                "analysis": {
                    "summary": {
                        "total_findings": total,
                        "critical_issues": critical,
                        "warnings": warnings,
                        "compliant_systems": compliant,
                        "compliance_score": round((compliant / total * 100), 1) if total > 0 else 0
                    },
                    "ai_analysis": f"""
Based on the compliance scan results, your organization has {critical} critical issues that require immediate attention:

**Critical Findings:**
- {critical} systems are failing compliance checks
- Key issues include End-of-Life systems and security vulnerabilities
- Systems past EOL pose significant security and compliance risks

**Recommendations:**
1. **Immediate Action Required:** Address EOL systems within 24-48 hours
2. **Security Patches:** Apply critical vulnerability fixes immediately  
3. **Planning:** Develop upgrade roadmap for warning systems
4. **Monitoring:** Implement continuous compliance monitoring

**Priority Order:**
1. Legacy systems past End-of-Life (highest risk)
2. Systems with known exploited vulnerabilities
3. Systems approaching EOL dates
4. Configuration compliance issues

This represents a {round((compliant / total * 100), 1)}% compliance score, indicating significant room for improvement.
                    """,
                    "recommendations": [
                        {
                            "priority": "P1_CRITICAL",
                            "title": "Address End-of-Life Systems",
                            "description": f"Found {len([f for f in findings if 'eol' in f.reason.lower()])} systems past EOL",
                            "action": "Plan immediate upgrade or replacement",
                            "timeline": "24-48 hours"
                        }
                    ]
                },
                "generated_by": "rule_based",
                "timestamp": datetime.now().isoformat()
            }
            
    except Exception as e:
        logger.error(f"Error generating compliance analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate analysis")

def generate_simple_answer(question: str) -> str:
    """Fallback rule-based responses when AI is not available"""
    question_lower = question.lower()
    
    if "eol" in question_lower or "end-of-life" in question_lower:
        return """Based on your current compliance findings, you have systems past their End-of-Life (EOL) date that require immediate attention:

**Critical Systems:**
- legacy-dc-01: Past EOL since 2020 (Finance)
- core-switch-01: Past EOS since 2019 (IT Operations)

**Immediate Actions:**
1. **Risk Assessment**: Evaluate business impact of EOL systems
2. **Upgrade Planning**: Create timeline for supported version migration
3. **Temporary Controls**: Implement additional monitoring and network segmentation
4. **Executive Briefing**: Communicate risks to management

**Timeline:** Critical systems should be upgraded within 24-48 hours due to security and compliance risks."""

    elif "vulnerability" in question_lower or "patch" in question_lower:
        return """Your environment has critical vulnerabilities requiring immediate attention:

**Critical Finding:**
- db-server-prod: CVE-2023-12345 (CISA Known Exploited Vulnerability)

**Patching Priority:**
- **Critical/KEV vulnerabilities**: Immediate (within hours)
- **High vulnerabilities**: 7 days
- **Medium vulnerabilities**: 30 days
- **Low vulnerabilities**: 90 days

**Immediate Actions:**
1. Apply security patch for CVE-2023-12345 immediately
2. Review CISA KEV catalog for other exposures
3. Implement emergency change procedures if needed
4. Monitor for exploitation attempts"""

    elif "compliance" in question_lower or "score" in question_lower:
        return """Your current compliance posture shows significant risks requiring attention:

**Current Status:**
- Compliance Score: 20% (1 of 5 systems compliant)
- Critical Issues: 3 systems
- Warnings: 1 system

**Key Risk Areas:**
1. **Lifecycle Management**: Multiple EOL/EOS systems
2. **Vulnerability Management**: Critical unpatched vulnerabilities
3. **Change Management**: Systems requiring immediate updates

**Improvement Plan:**
1. Address critical EOL systems (P1)
2. Implement vulnerability management program
3. Establish regular compliance monitoring
4. Create executive compliance dashboard"""

    else:
        return f"""I can help with compliance guidance based on your current findings:

**Your Current Issues:**
- 3 critical compliance failures
- 1 system approaching EOL
- 1 system with known exploited vulnerability

**I can assist with:**
- EOL system remediation strategies
- Vulnerability management prioritization
- Compliance framework requirements
- Risk assessment and mitigation

Ask specific questions like:
- "How do I handle EOL systems?"
- "What's my vulnerability exposure?"
- "How can I improve my compliance score?"

Your question: "{question}" - Please provide more details for specific guidance."""

# Background task for scanning
async def run_compliance_scan(scan_id: str, scan_request: ScanRequest):
    """Run compliance scan in background"""
    try:
        scan_data = active_scans[scan_id]
        
        for i, target_ip in enumerate(scan_request.target_ips):
            await asyncio.sleep(2)
            
            scan_data["completed"] = i + 1
            scan_data["progress"] = (i + 1) / len(scan_request.target_ips) * 100
            
            await manager.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": scan_data["progress"],
                "completed": scan_data["completed"],
                "total": scan_data["total"]
            })
        
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

# WebSocket endpoint
@app.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(5)
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.now().isoformat()
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Static file serving
try:
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
except Exception as e:
    logger.warning(f"Static files not available: {e}")

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve enhanced dashboard"""
    try:
        dashboard_file = Path(__file__).parent / "static" / "simple-dashboard.html"
        if dashboard_file.exists():
            return FileResponse(dashboard_file)
        else:
            return HTMLResponse(content="""
<h1>🏢 Enterprise CMDB Compliance Tool with AI</h1>
<p>Enhanced version with real OpenAI integration</p>
<ul>
<li><a href="/api/docs">API Documentation</a></li>
<li><a href="/api/v1/health">Health Check</a></li>
</ul>
""")
    except Exception as e:
        logger.error(f"Error serving root: {e}")
        return HTMLResponse(content="<h1>API Server Running</h1>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "enhanced_api_server:app",
        host="0.0.0.0",
        port=8002,
        reload=True,
        log_level="info"
    )