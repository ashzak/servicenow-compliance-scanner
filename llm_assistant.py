#!/usr/bin/env python3
"""
Enterprise CMDB Compliance Tool - LLM Assistant with RAG
AI-powered compliance assistant using vLLM + Llama 3.x with RAG architecture
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid

# LLM and RAG imports with fallbacks
try:
    import openai
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False

try:
    import chromadb
    from chromadb.config import Settings
    VECTOR_DB_AVAILABLE = True
except ImportError:
    VECTOR_DB_AVAILABLE = False

logger = logging.getLogger(__name__)

class ComplianceAssistant:
    """AI-powered compliance assistant with RAG capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.llm_client = None
        self.embeddings_model = None
        self.vector_db = None
        self.knowledge_base = {}
        
        # Initialize components based on available dependencies
        self._initialize_llm()
        self._initialize_embeddings()
        self._initialize_vector_db()
        self._load_knowledge_base()
    
    def _initialize_llm(self):
        """Initialize LLM client (OpenAI API compatible)"""
        try:
            if OPENAI_AVAILABLE:
                # Support for both OpenAI and vLLM endpoints
                api_key = self.config.get("llm", {}).get("api_key", "demo-key")
                base_url = self.config.get("llm", {}).get("base_url")
                
                if base_url:
                    # vLLM server endpoint
                    self.llm_client = AsyncOpenAI(
                        api_key=api_key,
                        base_url=base_url
                    )
                    logger.info(f"Initialized vLLM client with endpoint: {base_url}")
                else:
                    # Standard OpenAI API
                    self.llm_client = AsyncOpenAI(api_key=api_key)
                    logger.info("Initialized OpenAI client")
            else:
                logger.warning("OpenAI library not available, using mock LLM responses")
                self.llm_client = MockLLMClient()
                
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            self.llm_client = MockLLMClient()
    
    def _initialize_embeddings(self):
        """Initialize sentence transformer for embeddings"""
        try:
            if EMBEDDINGS_AVAILABLE:
                model_name = self.config.get("embeddings", {}).get("model", "all-MiniLM-L6-v2")
                self.embeddings_model = SentenceTransformer(model_name)
                logger.info(f"Initialized embeddings model: {model_name}")
            else:
                logger.warning("Sentence transformers not available, using mock embeddings")
                self.embeddings_model = MockEmbeddingsModel()
                
        except Exception as e:
            logger.error(f"Failed to initialize embeddings model: {e}")
            self.embeddings_model = MockEmbeddingsModel()
    
    def _initialize_vector_db(self):
        """Initialize ChromaDB for vector storage"""
        try:
            if VECTOR_DB_AVAILABLE:
                # Create persistent ChromaDB client
                db_path = self.config.get("vector_db", {}).get("path", "./chroma_db")
                
                self.vector_db = chromadb.PersistentClient(
                    path=db_path,
                    settings=Settings(anonymized_telemetry=False)
                )
                
                # Get or create collection for compliance knowledge
                self.knowledge_collection = self.vector_db.get_or_create_collection(
                    name="compliance_knowledge",
                    metadata={"description": "CMDB compliance policies and findings"}
                )
                
                logger.info(f"Initialized ChromaDB at: {db_path}")
            else:
                logger.warning("ChromaDB not available, using in-memory vector storage")
                self.vector_db = MockVectorDB()
                self.knowledge_collection = self.vector_db.get_collection("compliance_knowledge")
                
        except Exception as e:
            logger.error(f"Failed to initialize vector database: {e}")
            self.vector_db = MockVectorDB()
            self.knowledge_collection = self.vector_db.get_collection("compliance_knowledge")
    
    def _load_knowledge_base(self):
        """Load compliance knowledge base for RAG"""
        
        # Load compliance policies and best practices
        compliance_knowledge = [
            {
                "id": "eol_policy",
                "title": "End-of-Life (EOL) Compliance Policy",
                "content": """
                Systems that have reached End-of-Life (EOL) are no longer supported by vendors and pose significant security risks.
                EOL systems should be upgraded or replaced immediately as they:
                - No longer receive security patches
                - May have known vulnerabilities
                - Are not supported by vendors
                - May violate compliance frameworks (SOX, HIPAA, PCI-DSS)
                
                Remediation: Plan immediate upgrade to supported version or system replacement.
                Priority: P1 Critical - Must be addressed within 24-48 hours.
                """,
                "category": "policy",
                "tags": ["eol", "security", "compliance"]
            },
            {
                "id": "eos_policy", 
                "title": "End-of-Support (EOS) Compliance Policy",
                "content": """
                Systems approaching or past End-of-Support (EOS) require careful migration planning.
                EOS systems may still receive critical security patches but:
                - Extended support is often expensive
                - Features and functionality are frozen
                - Migration should be planned before EOS date
                
                Remediation: Begin migration planning 6-12 months before EOS date.
                Priority: P2 High - Plan migration within 30-90 days.
                """,
                "category": "policy",
                "tags": ["eos", "migration", "planning"]
            },
            {
                "id": "vulnerability_management",
                "title": "Vulnerability Management Best Practices",
                "content": """
                Systems with known exploited vulnerabilities (KEV) require immediate attention:
                - CISA Known Exploited Vulnerabilities catalog indicates active exploitation
                - Critical and high-severity CVEs should be patched within SLA
                - Zero-day vulnerabilities require emergency response
                
                Patching SLAs:
                - Critical vulnerabilities: 72 hours
                - High vulnerabilities: 7 days  
                - Medium vulnerabilities: 30 days
                - Low vulnerabilities: 90 days
                """,
                "category": "vulnerability",
                "tags": ["vulnerability", "patching", "kev", "cve"]
            },
            {
                "id": "business_unit_requirements",
                "title": "Business Unit Specific Requirements",
                "content": """
                Different business units have specific compliance requirements:
                
                Healthcare/HIPAA:
                - Enhanced encryption requirements
                - Audit logging mandatory
                - Risk assessment documentation
                - Breach notification procedures
                
                Financial/SOX:
                - Change control processes
                - Segregation of duties
                - Financial reporting system controls
                - Regular compliance audits
                
                Manufacturing:
                - High availability requirements
                - Safety system protections
                - Operational technology (OT) considerations
                """,
                "category": "business_requirements",
                "tags": ["hipaa", "sox", "manufacturing", "business_units"]
            },
            {
                "id": "remediation_strategies",
                "title": "Common Remediation Strategies",
                "content": """
                Effective remediation strategies for compliance violations:
                
                Operating System Upgrades:
                1. Assess application compatibility
                2. Plan maintenance windows
                3. Create rollback procedures  
                4. Test in staging environment
                5. Coordinate with business stakeholders
                
                Network Device Updates:
                1. Review firmware compatibility
                2. Backup current configuration
                3. Schedule during maintenance windows
                4. Test connectivity after update
                5. Document configuration changes
                
                Application Patching:
                1. Review vendor patch notes
                2. Test in development environment
                3. Coordinate with application owners
                4. Plan rollback strategy
                5. Monitor post-deployment
                """,
                "category": "remediation",
                "tags": ["remediation", "upgrades", "patching", "procedures"]
            }
        ]
        
        # Add knowledge to vector database
        for knowledge in compliance_knowledge:
            self._add_to_knowledge_base(knowledge)
    
    def _add_to_knowledge_base(self, knowledge: Dict[str, Any]):
        """Add knowledge item to vector database"""
        try:
            # Generate embeddings for the content
            content = f"{knowledge['title']}\n\n{knowledge['content']}"
            
            if hasattr(self.embeddings_model, 'encode'):
                embedding = self.embeddings_model.encode(content).tolist()
            else:
                embedding = self.embeddings_model.get_embedding(content)
            
            # Add to vector database
            self.knowledge_collection.add(
                documents=[content],
                embeddings=[embedding],
                metadatas=[{
                    "id": knowledge["id"],
                    "title": knowledge["title"],
                    "category": knowledge["category"],
                    "tags": ",".join(knowledge["tags"])
                }],
                ids=[knowledge["id"]]
            )
            
            logger.debug(f"Added knowledge item: {knowledge['id']}")
            
        except Exception as e:
            logger.error(f"Failed to add knowledge item {knowledge['id']}: {e}")
    
    async def ask_question(
        self, 
        question: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Ask a question to the compliance assistant"""
        
        try:
            # Retrieve relevant knowledge using RAG
            relevant_knowledge = await self._retrieve_knowledge(question)
            
            # Build context-aware prompt
            prompt = await self._build_prompt(question, relevant_knowledge, context)
            
            # Generate response using LLM
            response = await self._generate_response(prompt)
            
            return {
                "question": question,
                "answer": response,
                "sources": [k["metadata"]["title"] for k in relevant_knowledge],
                "timestamp": datetime.now().isoformat(),
                "context_used": bool(context)
            }
            
        except Exception as e:
            logger.error(f"Error processing question: {e}")
            return {
                "question": question,
                "answer": f"I apologize, but I encountered an error processing your question: {str(e)}",
                "sources": [],
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }
    
    async def _retrieve_knowledge(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """Retrieve relevant knowledge using semantic search"""
        
        try:
            # Generate query embedding
            if hasattr(self.embeddings_model, 'encode'):
                query_embedding = self.embeddings_model.encode(query).tolist()
            else:
                query_embedding = self.embeddings_model.get_embedding(query)
            
            # Search vector database
            results = self.knowledge_collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
            
            # Format results
            knowledge_items = []
            for i in range(len(results["documents"][0])):
                knowledge_items.append({
                    "content": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i] if "distances" in results else 0.0
                })
            
            return knowledge_items
            
        except Exception as e:
            logger.error(f"Error retrieving knowledge: {e}")
            return []
    
    async def _build_prompt(
        self, 
        question: str, 
        knowledge: List[Dict[str, Any]], 
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build context-aware prompt for LLM"""
        
        prompt_parts = [
            "You are an expert CMDB compliance assistant helping with enterprise IT compliance questions.",
            "Use the provided knowledge base and context to give accurate, actionable advice.",
            "",
            "KNOWLEDGE BASE:",
        ]
        
        # Add relevant knowledge
        for i, item in enumerate(knowledge, 1):
            prompt_parts.extend([
                f"## Source {i}: {item['metadata']['title']}",
                item["content"],
                ""
            ])
        
        # Add current context if provided
        if context:
            prompt_parts.extend([
                "CURRENT CONTEXT:",
                f"- Current findings: {len(context.get('findings', []))} compliance issues",
                f"- Systems scanned: {context.get('systems_count', 'Unknown')}",
                f"- Last scan: {context.get('last_scan', 'Unknown')}",
                ""
            ])
            
            # Add specific finding details if available
            if context.get('findings'):
                prompt_parts.append("Recent compliance findings:")
                for finding in context['findings'][:5]:  # Limit to 5 most recent
                    prompt_parts.append(
                        f"- {finding.get('ci_name', 'Unknown')}: {finding.get('status', 'unknown')} "
                        f"({finding.get('reason', 'No reason provided')})"
                    )
                prompt_parts.append("")
        
        prompt_parts.extend([
            "QUESTION:",
            question,
            "",
            "Please provide a helpful, accurate response based on the knowledge base and context. "
            "Include specific recommendations and next steps where appropriate. "
            "If you reference information from the knowledge base, mention the relevant source."
        ])
        
        return "\n".join(prompt_parts)
    
    async def _generate_response(self, prompt: str) -> str:
        """Generate LLM response to prompt"""
        
        try:
            model = self.config.get("llm", {}).get("model", "gpt-3.5-turbo")
            max_tokens = self.config.get("llm", {}).get("max_tokens", 1000)
            temperature = self.config.get("llm", {}).get("temperature", 0.1)
            
            if hasattr(self.llm_client, 'chat'):
                # Real OpenAI/vLLM client
                response = await self.llm_client.chat.completions.create(
                    model=model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a helpful and knowledgeable CMDB compliance assistant."
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        }
                    ],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                
                return response.choices[0].message.content
            else:
                # Mock client
                return await self.llm_client.generate_response(prompt)
                
        except Exception as e:
            logger.error(f"Error generating LLM response: {e}")
            return f"I apologize, but I'm unable to generate a response right now. Error: {str(e)}"
    
    async def analyze_compliance_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance findings and provide insights"""
        
        try:
            # Prepare analysis context
            context = {
                "findings": findings,
                "systems_count": len(set(f.get("ci_id") for f in findings)),
                "last_scan": datetime.now().isoformat()
            }
            
            # Generate summary statistics
            status_counts = {}
            risk_scores = []
            business_units = set()
            
            for finding in findings:
                status = finding.get("status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
                
                risk_score = finding.get("risk_score", 0)
                risk_scores.append(risk_score)
                
                bu = finding.get("business_unit")
                if bu:
                    business_units.add(bu)
            
            # Calculate metrics
            total_findings = len(findings)
            avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            compliance_score = (status_counts.get("pass", 0) / total_findings * 100) if total_findings > 0 else 0
            
            # Build analysis question
            analysis_question = f"""
            Please analyze these compliance findings and provide insights:
            
            Summary:
            - Total findings: {total_findings}
            - Status breakdown: {status_counts}
            - Average risk score: {avg_risk_score:.1f}
            - Compliance score: {compliance_score:.1f}%
            - Business units affected: {len(business_units)}
            
            What are the key risks and recommended actions?
            """
            
            # Get AI analysis
            analysis_result = await self.ask_question(analysis_question, context)
            
            return {
                "summary": {
                    "total_findings": total_findings,
                    "status_counts": status_counts,
                    "average_risk_score": round(avg_risk_score, 1),
                    "compliance_score": round(compliance_score, 1),
                    "business_units_affected": len(business_units)
                },
                "ai_analysis": analysis_result["answer"],
                "recommendations": await self._generate_recommendations(findings),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing compliance findings: {e}")
            return {
                "summary": {"error": str(e)},
                "ai_analysis": "Unable to analyze findings due to an error.",
                "recommendations": [],
                "timestamp": datetime.now().isoformat()
            }
    
    async def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate specific recommendations based on findings"""
        
        recommendations = []
        
        # Group findings by type
        eol_systems = [f for f in findings if "eol" in f.get("reason", "").lower()]
        high_risk = [f for f in findings if f.get("risk_score", 0) >= 80]
        failed_systems = [f for f in findings if f.get("status") == "fail"]
        
        # Generate specific recommendations
        if eol_systems:
            recommendations.append({
                "priority": "P1_CRITICAL",
                "title": "Address End-of-Life Systems",
                "description": f"Found {len(eol_systems)} systems past End-of-Life",
                "action": "Plan immediate upgrade or replacement",
                "timeline": "24-48 hours",
                "affected_systems": [f.get("ci_name") for f in eol_systems[:5]]
            })
        
        if high_risk:
            recommendations.append({
                "priority": "P1_CRITICAL", 
                "title": "Mitigate High-Risk Systems",
                "description": f"Found {len(high_risk)} systems with risk score ≥80",
                "action": "Apply security patches and implement compensating controls",
                "timeline": "72 hours",
                "affected_systems": [f.get("ci_name") for f in high_risk[:5]]
            })
        
        if failed_systems:
            recommendations.append({
                "priority": "P2_HIGH",
                "title": "Fix Failed Compliance Checks", 
                "description": f"Found {len(failed_systems)} systems failing compliance",
                "action": "Review and remediate compliance violations",
                "timeline": "1-2 weeks",
                "affected_systems": [f.get("ci_name") for f in failed_systems[:5]]
            })
        
        return recommendations

# Mock implementations for when dependencies are not available
class MockLLMClient:
    """Mock LLM client for when OpenAI is not available"""
    
    async def generate_response(self, prompt: str) -> str:
        """Generate mock response based on prompt keywords"""
        
        prompt_lower = prompt.lower()
        
        if "eol" in prompt_lower or "end-of-life" in prompt_lower:
            return """
Based on the compliance findings, I can see you have systems that are past their End-of-Life (EOL) date. 
This is a critical security risk that requires immediate attention.

**Immediate Actions Required:**
1. **Inventory Review**: Identify all EOL systems and their business criticality
2. **Risk Assessment**: Evaluate the security and compliance risks
3. **Upgrade Planning**: Create a timeline for upgrading to supported versions
4. **Temporary Mitigations**: Implement network segmentation and monitoring

**Recommended Timeline:**
- Critical systems: 24-48 hours
- High-priority systems: 1-2 weeks  
- Standard systems: 30-60 days

**Next Steps:**
1. Contact vendors for upgrade paths
2. Schedule maintenance windows
3. Test upgrades in staging environment
4. Coordinate with business stakeholders

This should be treated as a P1 Critical priority due to security and compliance implications.
            """
        elif "vulnerability" in prompt_lower or "cve" in prompt_lower:
            return """
I see you're asking about vulnerability management. Here's my analysis:

**Critical Vulnerabilities:**
Vulnerabilities with known exploits should be patched immediately (within 72 hours).

**Patching Priority:**
1. **Critical (CVSS 9.0-10.0)**: 72 hours
2. **High (CVSS 7.0-8.9)**: 7 days
3. **Medium (CVSS 4.0-6.9)**: 30 days
4. **Low (CVSS 0.1-3.9)**: 90 days

**Best Practices:**
- Monitor CISA Known Exploited Vulnerabilities catalog
- Implement automated patch management where possible
- Test patches in staging before production deployment
- Maintain complete inventory of software and versions

Would you like me to help prioritize specific vulnerabilities or create a patching schedule?
            """
        elif "compliance" in prompt_lower:
            return """
Based on your compliance findings, here's my assessment:

**Key Compliance Areas:**
1. **System Lifecycle Management**: Ensure all systems are within supported lifecycle
2. **Vulnerability Management**: Maintain current patching levels
3. **Configuration Management**: Follow security baselines and standards
4. **Documentation**: Maintain accurate CMDB records

**Regulatory Considerations:**
- **HIPAA**: Enhanced security controls for healthcare data
- **SOX**: Financial reporting system controls and change management
- **PCI-DSS**: Payment card industry security requirements

**Recommendations:**
1. Implement automated compliance scanning
2. Create compliance dashboards for management visibility
3. Establish regular compliance review cycles
4. Document remediation procedures and timelines

The goal is to maintain continuous compliance rather than point-in-time assessments.
            """
        else:
            return """
Thank you for your question about CMDB compliance. Based on the available information, I recommend:

1. **Assessment**: Review current compliance posture and identify gaps
2. **Prioritization**: Focus on critical and high-risk findings first  
3. **Planning**: Create detailed remediation plans with timelines
4. **Implementation**: Execute changes during appropriate maintenance windows
5. **Monitoring**: Implement ongoing compliance monitoring

For more specific guidance, please provide additional details about your particular compliance challenges or findings.

I'm here to help with any specific compliance questions you may have!
            """

class MockEmbeddingsModel:
    """Mock embeddings model for when sentence-transformers is not available"""
    
    def get_embedding(self, text: str) -> List[float]:
        """Generate mock embedding based on text hash"""
        # Simple hash-based mock embedding
        import hashlib
        text_hash = hashlib.md5(text.encode()).hexdigest()
        # Convert hex to list of floats
        embedding = []
        for i in range(0, len(text_hash), 2):
            hex_pair = text_hash[i:i+2]
            embedding.append(int(hex_pair, 16) / 255.0)
        
        # Pad to fixed length
        while len(embedding) < 384:
            embedding.append(0.0)
        
        return embedding[:384]

class MockVectorDB:
    """Mock vector database for when ChromaDB is not available"""
    
    def __init__(self):
        self.collections = {}
    
    def get_collection(self, name: str):
        if name not in self.collections:
            self.collections[name] = MockCollection()
        return self.collections[name]

class MockCollection:
    """Mock collection for vector storage"""
    
    def __init__(self):
        self.documents = []
        self.embeddings = []
        self.metadatas = []
        self.ids = []
    
    def add(self, documents, embeddings, metadatas, ids):
        """Add documents to collection"""
        self.documents.extend(documents)
        self.embeddings.extend(embeddings)
        self.metadatas.extend(metadatas)
        self.ids.extend(ids)
    
    def query(self, query_embeddings, n_results=3, include=None):
        """Query collection (returns mock results)"""
        include = include or ["documents", "metadatas"]
        
        # Return a subset of stored documents as mock results
        result_count = min(n_results, len(self.documents))
        
        result = {}
        if "documents" in include:
            result["documents"] = [self.documents[:result_count]]
        if "metadatas" in include:
            result["metadatas"] = [self.metadatas[:result_count]]
        if "distances" in include:
            result["distances"] = [[0.1 * i for i in range(result_count)]]
        
        return result

# Example usage and testing
async def demo_llm_assistant():
    """Demonstrate LLM assistant capabilities"""
    
    config = {
        "llm": {
            "provider": "openai",
            "model": "gpt-3.5-turbo",
            "api_key": os.getenv("OPENAI_API_KEY", "demo-key"),
            "base_url": None,  # Set to vLLM endpoint if using local model
            "max_tokens": 1000,
            "temperature": 0.1
        },
        "embeddings": {
            "model": "all-MiniLM-L6-v2"
        },
        "vector_db": {
            "path": "./demo_chroma_db"
        }
    }
    
    # Create assistant
    assistant = ComplianceAssistant(config)
    
    print("🤖 Enterprise CMDB Compliance Assistant Demo")
    print("=" * 50)
    
    # Demo questions
    questions = [
        "What should I do about systems that are past End-of-Life?",
        "How should I prioritize vulnerability patching?",
        "What are the compliance requirements for healthcare systems?",
        "Can you explain the difference between EOL and EOS?"
    ]
    
    for question in questions:
        print(f"\n❓ Question: {question}")
        print("-" * 40)
        
        result = await assistant.ask_question(question)
        print(f"🤖 Answer: {result['answer']}")
        
        if result.get('sources'):
            print(f"📚 Sources: {', '.join(result['sources'])}")
        
        print()
    
    # Demo compliance analysis
    print("\n📊 COMPLIANCE FINDINGS ANALYSIS")
    print("-" * 40)
    
    sample_findings = [
        {
            "ci_id": "ci_001",
            "ci_name": "legacy-dc-01", 
            "status": "fail",
            "reason": "Past End-of-Life (2020-01-14)",
            "risk_score": 90,
            "business_unit": "Finance"
        },
        {
            "ci_id": "ci_002",
            "ci_name": "web-app-02",
            "status": "warn", 
            "reason": "EOL in 45 days",
            "risk_score": 60,
            "business_unit": "Marketing"
        },
        {
            "ci_id": "ci_003",
            "ci_name": "app-server-03",
            "status": "pass",
            "reason": "Compliant - Windows Server 2022", 
            "risk_score": 0,
            "business_unit": "Engineering"
        }
    ]
    
    analysis = await assistant.analyze_compliance_findings(sample_findings)
    
    print("📈 Summary:")
    for key, value in analysis["summary"].items():
        print(f"  • {key}: {value}")
    
    print(f"\n🤖 AI Analysis:\n{analysis['ai_analysis']}")
    
    print("\n💡 Recommendations:")
    for i, rec in enumerate(analysis["recommendations"], 1):
        print(f"  {i}. [{rec['priority']}] {rec['title']}")
        print(f"     {rec['description']}")
        print(f"     Action: {rec['action']}")
        print(f"     Timeline: {rec['timeline']}")
        print()

if __name__ == "__main__":
    asyncio.run(demo_llm_assistant())