#!/usr/bin/env python3
"""
LLM GraphQL Orchestrator - Intelligent Query Generation and Execution
Combines LLM reasoning with GraphQL queries and RAG for compliance intelligence
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import re

# GraphQL and HTTP imports
try:
    import aiohttp
    import strawberry
    from graphql import build_client_schema, get_introspection_query
    GRAPHQL_DEPS_AVAILABLE = True
except ImportError:
    GRAPHQL_DEPS_AVAILABLE = False

# OpenAI imports
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

# Vector database imports
try:
    import chromadb
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class QueryIntent:
    """Parsed user intent for GraphQL query generation"""
    intent_type: str  # "summary", "search", "analysis", "action"
    entities: List[str]  # business_unit, ci_class, status, etc.
    filters: Dict[str, Any]
    aggregation: Optional[str]  # count, avg, max, etc.
    time_scope: Optional[str]  # recent, last_week, etc.
    confidence: float

@dataclass
class GraphQLQuery:
    """Generated GraphQL query with metadata"""
    query: str
    variables: Dict[str, Any]
    operation_type: str  # query, mutation, subscription
    expected_fields: List[str]
    confidence: float

class LLMGraphQLOrchestrator:
    """Intelligent LLM that orchestrates GraphQL queries and provides RAG-enhanced responses"""
    
    def __init__(self, config: Dict[str, Any]):
        self.graphql_endpoint = config.get("graphql_endpoint", "http://localhost:8001/graphql")
        self.openai_api_key = config.get("openai_api_key")
        self.chroma_collection_name = config.get("chroma_collection", "compliance_rag")
        
        # Initialize components
        self.graphql_schema = None
        self.query_templates = {}
        self.vector_store = None
        self.openai_client = None
        
        # Query generation prompts
        self.intent_classification_prompt = """
You are a compliance data analyst. Classify the user's question into one of these intents:

INTENTS:
- summary: Overall compliance status, dashboards, totals
- search: Find specific systems, CIs, or findings  
- analysis: Compare, rank, analyze trends or patterns
- action: Start scans, investigate issues, get recommendations

ENTITIES (extract if mentioned):
- business_unit: Finance, Healthcare, IT Operations, etc.
- ci_class: servers, network devices, databases, etc.
- status: pass, fail, warn, critical, compliant
- risk_level: high, medium, low, critical
- time_scope: recent, today, last week, etc.

Example:
User: "Show me critical systems in Finance"
Output: {
  "intent_type": "search",
  "entities": ["Finance", "critical"],
  "filters": {"business_unit": "Finance", "status": "fail"},
  "confidence": 0.9
}

User question: "{question}"
Output (JSON only):"""

        self.graphql_generation_prompt = """
You are a GraphQL query generator for a compliance monitoring system. Generate efficient GraphQL queries based on user intent.

AVAILABLE SCHEMA OPERATIONS:
- complianceFindings(filter: ComplianceFilter, limit: Int, offset: Int): [ComplianceFinding]
- complianceSummary: ComplianceSummary  
- businessUnits: [BusinessUnit]
- ci(id: String): CI
- startComplianceScan(ciIds: [String], businessUnit: String): ScanStatus

FILTERS:
- ComplianceFilter: status, businessUnit, ciClass, minRiskScore, maxRiskScore, daysSinceScan

AVAILABLE TYPES:
- ComplianceFinding: id, status, reason, riskScore, ci, osFacts, evaluatedAt
- CI: name, businessUnit, ipAddress, ciClass, criticality
- OSFacts: product, version, connectorUsed
- BusinessUnit: name, systemCount, criticalCount, complianceScore

Intent: {intent}
Generate GraphQL query (JSON format):
{{
  "query": "query {{ ... }}",
  "variables": {{}},
  "operation_type": "query",
  "expected_fields": ["field1", "field2"]
}}"""

    async def initialize(self):
        """Initialize all components"""
        try:
            # Initialize OpenAI
            if OPENAI_AVAILABLE and self.openai_api_key:
                self.openai_client = openai.AsyncOpenAI(api_key=self.openai_api_key)
                logger.info("✅ OpenAI client initialized")
            
            # Initialize vector store
            if CHROMADB_AVAILABLE:
                await self._initialize_vector_store()
            
            # Load GraphQL schema
            await self._load_graphql_schema()
            
            # Load query templates
            self._load_query_templates()
            
            logger.info("✅ LLM GraphQL Orchestrator initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize LLM GraphQL Orchestrator: {e}")
    
    async def _initialize_vector_store(self):
        """Initialize ChromaDB for RAG"""
        try:
            client = chromadb.Client()
            self.vector_store = client.get_or_create_collection(
                name=self.chroma_collection_name,
                metadata={"description": "Compliance knowledge base for RAG"}
            )
            
            # Add some example compliance knowledge
            await self._populate_knowledge_base()
            logger.info("✅ Vector store initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
    
    async def _populate_knowledge_base(self):
        """Populate vector store with compliance knowledge"""
        
        compliance_docs = [
            {
                "id": "eol_policy",
                "text": "Systems past End-of-Life (EOL) pose critical security risks and must be upgraded immediately. EOL systems receive no security patches.",
                "metadata": {"category": "policy", "risk_level": "critical"}
            },
            {
                "id": "business_unit_finance",
                "text": "Finance systems require SOX compliance and have stricter security requirements. All critical findings must be resolved within 24 hours.",
                "metadata": {"category": "business_unit", "unit": "finance"}
            },
            {
                "id": "network_devices", 
                "text": "Network devices (routers, switches, firewalls) are critical infrastructure. Use NAPALM and SNMP for monitoring. Focus on firmware versions and known vulnerabilities.",
                "metadata": {"category": "asset_type", "type": "network"}
            },
            {
                "id": "risk_scoring",
                "text": "Risk scores: 0-30 Low, 31-60 Medium, 61-85 High, 86-100 Critical. Critical systems require immediate attention and executive notification.",
                "metadata": {"category": "scoring", "type": "risk"}
            },
            {
                "id": "compliance_frameworks",
                "text": "Common compliance frameworks: SOX (Finance), HIPAA (Healthcare), PCI-DSS (Payment), ISO 27001 (Security). Each has specific requirements for system lifecycle management.",
                "metadata": {"category": "compliance", "type": "frameworks"}
            }
        ]
        
        if self.vector_store:
            for doc in compliance_docs:
                self.vector_store.add(
                    documents=[doc["text"]],
                    metadatas=[doc["metadata"]],
                    ids=[doc["id"]]
                )
    
    async def _load_graphql_schema(self):
        """Load GraphQL schema for query generation"""
        try:
            if not GRAPHQL_DEPS_AVAILABLE:
                logger.warning("GraphQL dependencies not available")
                return
            
            async with aiohttp.ClientSession() as session:
                introspection_query = get_introspection_query()
                async with session.post(
                    self.graphql_endpoint,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.graphql_schema = build_client_schema(result["data"])
                        logger.info("✅ GraphQL schema loaded")
                    else:
                        logger.warning(f"Failed to load GraphQL schema: {response.status}")
        
        except Exception as e:
            logger.error(f"Error loading GraphQL schema: {e}")
    
    def _load_query_templates(self):
        """Load common GraphQL query templates"""
        
        self.query_templates = {
            "compliance_summary": {
                "query": """
                query ComplianceDashboard {
                  complianceSummary {
                    totalSystems
                    compliantSystems
                    criticalSystems
                    complianceScore
                    avgRiskScore
                  }
                  businessUnits {
                    name
                    systemCount
                    criticalCount
                    complianceScore
                  }
                }""",
                "description": "Overall compliance dashboard"
            },
            
            "critical_systems": {
                "query": """
                query CriticalSystems($businessUnit: String, $minRiskScore: Int) {
                  complianceFindings(
                    filter: { 
                      status: FAIL
                      businessUnit: $businessUnit
                      minRiskScore: $minRiskScore
                    }
                    limit: 20
                  ) {
                    ci {
                      name
                      businessUnit
                      ipAddress
                      criticality
                    }
                    status
                    reason
                    riskScore
                    remediation
                    evaluatedAt
                  }
                }""",
                "description": "Find critical compliance violations"
            },
            
            "business_unit_analysis": {
                "query": """
                query BusinessUnitAnalysis($businessUnit: String!) {
                  businessUnits {
                    name
                    systemCount
                    criticalCount
                    complianceScore
                    avgRiskScore
                    systems {
                      name
                      ipAddress
                      criticality
                    }
                  }
                  complianceFindings(
                    filter: { businessUnit: $businessUnit }
                    limit: 50
                  ) {
                    ci { name }
                    status
                    reason
                    riskScore
                  }
                }""",
                "description": "Detailed business unit compliance analysis"
            },
            
            "network_devices": {
                "query": """
                query NetworkDeviceCompliance {
                  complianceFindings(
                    filter: { ciClass: "cmdb_ci_netgear" }
                  ) {
                    ci {
                      name
                      ipAddress
                      businessUnit
                    }
                    status
                    reason
                    riskScore
                    osFacts {
                      product
                      version
                      connectorUsed
                    }
                  }
                }""",
                "description": "Network device compliance status"
            }
        }
    
    async def process_question(self, question: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main orchestration method - processes user question through LLM + GraphQL + RAG"""
        
        try:
            logger.info(f"🤖 Processing question: {question}")
            
            # Step 1: Parse intent using LLM
            intent = await self._parse_intent(question)
            logger.info(f"📊 Parsed intent: {intent.intent_type} (confidence: {intent.confidence})")
            
            # Step 2: Generate GraphQL query
            graphql_query = await self._generate_graphql_query(intent, question)
            logger.info(f"🔍 Generated GraphQL query: {graphql_query.operation_type}")
            
            # Step 3: Execute GraphQL query
            query_result = await self._execute_graphql_query(graphql_query)
            
            # Step 4: Get relevant knowledge from RAG
            rag_context = await self._get_rag_context(question, intent)
            
            # Step 5: Generate intelligent response using LLM
            response = await self._generate_response(question, query_result, rag_context, intent)
            
            return {
                "answer": response,
                "intent": intent.__dict__,
                "graphql_query": graphql_query.query,
                "data": query_result,
                "rag_context": rag_context,
                "confidence": min(intent.confidence, graphql_query.confidence)
            }
            
        except Exception as e:
            logger.error(f"Error processing question: {e}")
            return {
                "answer": f"I encountered an error processing your question: {str(e)}",
                "error": str(e),
                "confidence": 0.0
            }
    
    async def _parse_intent(self, question: str) -> QueryIntent:
        """Parse user intent using LLM"""
        
        if not self.openai_client:
            # Fallback intent parsing
            return self._fallback_intent_parsing(question)
        
        try:
            prompt = self.intent_classification_prompt.format(question=question)
            
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a compliance data analyst that classifies user questions."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Parse JSON response
            try:
                result = json.loads(result_text)
                return QueryIntent(
                    intent_type=result.get("intent_type", "search"),
                    entities=result.get("entities", []),
                    filters=result.get("filters", {}),
                    aggregation=result.get("aggregation"),
                    time_scope=result.get("time_scope"),
                    confidence=result.get("confidence", 0.8)
                )
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM intent response: {result_text}")
                return self._fallback_intent_parsing(question)
        
        except Exception as e:
            logger.error(f"Error in intent parsing: {e}")
            return self._fallback_intent_parsing(question)
    
    def _fallback_intent_parsing(self, question: str) -> QueryIntent:
        """Fallback intent parsing using keyword matching"""
        
        question_lower = question.lower()
        
        # Determine intent type
        if any(word in question_lower for word in ["summary", "overview", "dashboard", "total", "how many"]):
            intent_type = "summary"
        elif any(word in question_lower for word in ["find", "show", "get", "list", "which"]):
            intent_type = "search"  
        elif any(word in question_lower for word in ["compare", "analyze", "rank", "worst", "best"]):
            intent_type = "analysis"
        elif any(word in question_lower for word in ["scan", "fix", "remediate", "start"]):
            intent_type = "action"
        else:
            intent_type = "search"
        
        # Extract entities
        entities = []
        filters = {}
        
        # Business units
        business_units = ["finance", "healthcare", "it operations", "marketing", "engineering"]
        for bu in business_units:
            if bu in question_lower:
                entities.append(bu.title())
                filters["businessUnit"] = bu.title()
        
        # Status keywords
        if any(word in question_lower for word in ["critical", "fail", "failing", "violation"]):
            entities.append("critical")
            filters["status"] = "FAIL"
        elif any(word in question_lower for word in ["warning", "warn"]):
            entities.append("warning")
            filters["status"] = "WARN"
        elif any(word in question_lower for word in ["compliant", "pass", "passing"]):
            entities.append("compliant")
            filters["status"] = "PASS"
        
        # Risk levels
        if any(word in question_lower for word in ["high risk", "dangerous"]):
            filters["minRiskScore"] = 80
        
        return QueryIntent(
            intent_type=intent_type,
            entities=entities,
            filters=filters,
            aggregation=None,
            time_scope=None,
            confidence=0.7
        )
    
    async def _generate_graphql_query(self, intent: QueryIntent, question: str) -> GraphQLQuery:
        """Generate GraphQL query based on intent"""
        
        # Check if we have a matching template
        template_key = self._find_matching_template(intent)
        if template_key:
            template = self.query_templates[template_key]
            return GraphQLQuery(
                query=template["query"],
                variables=intent.filters,
                operation_type="query",
                expected_fields=["data"],
                confidence=0.9
            )
        
        # Generate custom query using LLM if available
        if self.openai_client:
            return await self._llm_generate_query(intent, question)
        
        # Fallback to default query
        return self._fallback_query_generation(intent)
    
    def _find_matching_template(self, intent: QueryIntent) -> Optional[str]:
        """Find matching query template based on intent"""
        
        if intent.intent_type == "summary":
            return "compliance_summary"
        elif intent.intent_type == "search" and "critical" in intent.entities:
            return "critical_systems"
        elif "network" in intent.entities or "switch" in intent.entities or "router" in intent.entities:
            return "network_devices"
        elif len([e for e in intent.entities if e in ["Finance", "Healthcare", "IT Operations"]]) > 0:
            return "business_unit_analysis"
        
        return None
    
    async def _llm_generate_query(self, intent: QueryIntent, question: str) -> GraphQLQuery:
        """Generate GraphQL query using LLM"""
        
        try:
            prompt = self.graphql_generation_prompt.format(
                intent=json.dumps(intent.__dict__, default=str)
            )
            
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a GraphQL query generator for compliance monitoring."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            result_text = response.choices[0].message.content.strip()
            
            try:
                result = json.loads(result_text)
                return GraphQLQuery(
                    query=result["query"],
                    variables=result.get("variables", {}),
                    operation_type=result.get("operation_type", "query"),
                    expected_fields=result.get("expected_fields", []),
                    confidence=0.8
                )
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse LLM query response: {result_text}")
                return self._fallback_query_generation(intent)
        
        except Exception as e:
            logger.error(f"Error in LLM query generation: {e}")
            return self._fallback_query_generation(intent)
    
    def _fallback_query_generation(self, intent: QueryIntent) -> GraphQLQuery:
        """Fallback query generation"""
        
        if intent.intent_type == "summary":
            return GraphQLQuery(
                query=self.query_templates["compliance_summary"]["query"],
                variables={},
                operation_type="query",
                expected_fields=["complianceSummary"],
                confidence=0.6
            )
        else:
            # Default to compliance findings search
            return GraphQLQuery(
                query="""
                query DefaultSearch($filter: ComplianceFilter) {
                  complianceFindings(filter: $filter, limit: 10) {
                    ci { name, businessUnit }
                    status
                    reason
                    riskScore
                    evaluatedAt
                  }
                }""",
                variables={"filter": intent.filters} if intent.filters else {},
                operation_type="query",
                expected_fields=["complianceFindings"],
                confidence=0.5
            )
    
    async def _execute_graphql_query(self, graphql_query: GraphQLQuery) -> Dict[str, Any]:
        """Execute GraphQL query against the API"""
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "query": graphql_query.query,
                    "variables": graphql_query.variables
                }
                
                async with session.post(
                    self.graphql_endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        if "errors" in result:
                            logger.error(f"GraphQL errors: {result['errors']}")
                            return {"error": result["errors"]}
                        return result.get("data", {})
                    else:
                        logger.error(f"GraphQL request failed: {response.status}")
                        return {"error": f"HTTP {response.status}"}
        
        except Exception as e:
            logger.error(f"Error executing GraphQL query: {e}")
            return {"error": str(e)}
    
    async def _get_rag_context(self, question: str, intent: QueryIntent) -> List[str]:
        """Get relevant context from vector store (RAG)"""
        
        if not self.vector_store:
            return []
        
        try:
            # Query vector store for relevant compliance knowledge
            results = self.vector_store.query(
                query_texts=[question],
                n_results=3
            )
            
            if results and results.get("documents"):
                return results["documents"][0]
            
        except Exception as e:
            logger.error(f"Error querying vector store: {e}")
        
        return []
    
    async def _generate_response(
        self, 
        question: str, 
        query_result: Dict[str, Any], 
        rag_context: List[str],
        intent: QueryIntent
    ) -> str:
        """Generate intelligent response using LLM with GraphQL results and RAG context"""
        
        if not self.openai_client:
            return self._fallback_response_generation(query_result, intent)
        
        try:
            # Prepare context for LLM
            context_text = "\n\n".join([
                f"User Question: {question}",
                f"Query Results: {json.dumps(query_result, default=str, indent=2)}",
                f"Knowledge Base Context: {' '.join(rag_context)}" if rag_context else ""
            ])
            
            prompt = f"""
You are a compliance expert analyzing enterprise system data. Provide a clear, actionable response based on the GraphQL query results and knowledge base context.

Guidelines:
- Be specific with numbers and system names
- Highlight critical issues that need immediate attention
- Provide context about compliance implications
- Suggest concrete remediation steps when relevant
- Use business-friendly language while being technically accurate

Context:
{context_text}

Provide a comprehensive response:"""

            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a compliance expert providing analysis of enterprise system data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"Error generating LLM response: {e}")
            return self._fallback_response_generation(query_result, intent)
    
    def _fallback_response_generation(self, query_result: Dict[str, Any], intent: QueryIntent) -> str:
        """Fallback response generation without LLM"""
        
        if "error" in query_result:
            return f"I encountered an error retrieving the data: {query_result['error']}"
        
        # Simple response based on intent type
        if intent.intent_type == "summary":
            summary = query_result.get("complianceSummary", {})
            return f"""
Compliance Summary:
- Total Systems: {summary.get('totalSystems', 0)}
- Compliant Systems: {summary.get('compliantSystems', 0)}
- Critical Systems: {summary.get('criticalSystems', 0)}
- Compliance Score: {summary.get('complianceScore', 0)}%
- Average Risk Score: {summary.get('avgRiskScore', 0)}
"""
        
        elif intent.intent_type == "search":
            findings = query_result.get("complianceFindings", [])
            if not findings:
                return "No compliance findings match your query."
            
            response = f"Found {len(findings)} compliance findings:\n\n"
            for i, finding in enumerate(findings[:5], 1):
                ci = finding.get("ci", {})
                response += f"{i}. {ci.get('name', 'Unknown')} ({ci.get('businessUnit', 'N/A')})\n"
                response += f"   Status: {finding.get('status', 'Unknown')} | Risk Score: {finding.get('riskScore', 0)}\n"
                response += f"   Issue: {finding.get('reason', 'No details')}\n\n"
            
            return response
        
        return "I found some data but couldn't generate a detailed analysis. Please check the raw query results."

# Example usage and demo
async def demo_llm_orchestrator():
    """Demonstrate LLM GraphQL orchestration capabilities"""
    
    config = {
        "graphql_endpoint": "http://localhost:8001/graphql",
        "openai_api_key": "your-api-key-here",
        "chroma_collection": "compliance_demo"
    }
    
    orchestrator = LLMGraphQLOrchestrator(config)
    await orchestrator.initialize()
    
    # Test questions
    test_questions = [
        "Show me the overall compliance summary",
        "What are the critical systems in Finance?",
        "Which network devices have compliance issues?",
        "How many systems are failing compliance?",
        "Start a compliance scan for IT Operations"
    ]
    
    for question in test_questions:
        print(f"\n🤖 Question: {question}")
        result = await orchestrator.process_question(question)
        print(f"📊 Answer: {result['answer']}")
        print(f"🔍 Query: {result.get('graphql_query', 'N/A')}")
        print("-" * 80)

if __name__ == "__main__":
    asyncio.run(demo_llm_orchestrator())