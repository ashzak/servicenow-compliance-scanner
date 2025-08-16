# GraphQL API & Enhanced LLM Assistant - Enterprise CMDB Compliance Tool

## 🚀 Latest Updates

### GraphQL API Implementation
- **Full GraphQL Schema**: Comprehensive queries, mutations, and subscriptions
- **Interactive Playground**: Available at `http://localhost:8001/graphql`
- **Real-time Features**: WebSocket subscriptions for live compliance updates
- **Flexible Queries**: Request exactly the data you need in a single call

### Enhanced LLM Assistant with Intelligent Orchestration
- **Hybrid Intelligence**: Automatic routing between GraphQL data queries and RAG knowledge queries
- **Dynamic Query Generation**: LLM automatically generates GraphQL queries based on user intent
- **Context-Aware Responses**: Combines live data with compliance expertise
- **Enterprise-Grade Analysis**: Executive-level insights with actionable recommendations

## 🌐 API Endpoints

### REST API
- **URL**: `http://localhost:8001/api/docs`
- **Features**: Traditional REST endpoints with FastAPI documentation
- **Use Cases**: Direct API integration, mobile apps, simple queries

### GraphQL API  
- **URL**: `http://localhost:8001/graphql`
- **Features**: Flexible schema, real-time subscriptions, introspection
- **Use Cases**: Complex dashboards, custom reporting, efficient data fetching

### Enhanced LLM Assistant
- **Integration**: Both REST and GraphQL APIs
- **Intelligence**: Automatic query orchestration + RAG
- **Use Cases**: Natural language compliance analysis, executive reporting

## 🔧 Quick Start

### 1. Install Dependencies
```bash
pip install 'strawberry-graphql[fastapi]' aiohttp
```

### 2. Start Services
```bash
# Start the enhanced API server (includes GraphQL + LLM)
python3 api_server_simple.py

# Access GraphQL Playground
open http://localhost:8001/graphql
```

### 3. Test GraphQL Queries
```graphql
# Get compliance summary
query {
  complianceSummary {
    totalSystems
    complianceScore
    criticalSystems
  }
}

# Find critical systems in Finance
query {
  complianceFindings(filter: {status: FAIL, businessUnit: "Finance"}) {
    ci { name, businessUnit }
    reason
    riskScore
  }
}
```

### 4. Test Enhanced LLM Assistant
```bash
# Natural language queries with intelligent routing
curl -X POST http://localhost:8001/api/v1/assistant/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "Show me critical systems in Finance"}'

# Knowledge-based questions
curl -X POST http://localhost:8001/api/v1/assistant/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "What are SOX compliance requirements?"}'
```

## 🎯 Key Features

### GraphQL Schema Highlights
- **25+ Types**: Comprehensive compliance data model
- **Flexible Filtering**: Filter by status, business unit, risk score, etc.
- **Relationships**: Nested queries for CIs, OS facts, lifecycle data
- **Real-time**: Subscription support for live compliance monitoring

### LLM Orchestration Intelligence
- **Intent Classification**: Automatically determines if query needs data or knowledge
- **Dynamic Query Generation**: LLM creates GraphQL queries based on user intent  
- **Hybrid Responses**: Combines live data with compliance expertise
- **Confidence Scoring**: Provides confidence metrics for response quality

### Enterprise Capabilities
- **Executive Dashboards**: Complex multi-table queries in single requests
- **Business Unit Analysis**: Detailed compliance breakdown by organization
- **Network Device Monitoring**: Specialized queries for infrastructure components
- **Remediation Planning**: AI-powered recommendations with prioritization

## 📊 Example Use Cases

### 1. Executive Dashboard (GraphQL)
```graphql
query ExecutiveDashboard {
  complianceSummary {
    totalSystems
    complianceScore
    criticalSystems
  }
  businessUnits {
    name
    systemCount
    criticalCount
    complianceScore
  }
  criticalFindings: complianceFindings(filter: {status: FAIL}, limit: 5) {
    ci { name, businessUnit }
    reason
    riskScore
  }
}
```

### 2. Natural Language Analysis (Enhanced LLM)
**User**: "What's our biggest compliance risk right now?"
**Assistant**: Uses GraphQL to get live data + RAG for compliance context, provides comprehensive analysis with specific systems, risk scores, and remediation steps.

### 3. Network Operations (GraphQL)
```graphql
query NetworkCompliance {
  complianceFindings(filter: {ciClass: "cmdb_ci_netgear"}) {
    ci {
      name
      ipAddress
      businessUnit
    }
    status
    reason
    osFacts {
      product
      version
      connectorUsed
    }
  }
}
```

### 4. Real-time Monitoring (GraphQL Subscription)
```graphql
subscription ComplianceAlerts {
  complianceUpdates {
    ci { name, businessUnit }
    status
    reason
    riskScore
  }
}
```

## 🔍 Architecture Overview

### Request Flow
1. **User Query** → Intent Classification
2. **Data Query** → GraphQL Orchestrator → Live API → Enhanced Response
3. **Knowledge Query** → RAG Vector Store → Context Retrieval → LLM Response
4. **Hybrid Query** → Both paths combined for comprehensive analysis

### Components
- **GraphQL Schema**: Strawberry-based type system
- **LLM Orchestrator**: OpenAI-powered query generation
- **RAG System**: ChromaDB vector store with compliance knowledge
- **Intent Router**: Intelligent routing between data and knowledge paths

## 🚀 Benefits

### For Developers
- **Single Request**: Get complex nested data in one GraphQL call
- **Type Safety**: Strong typing with built-in validation
- **Self-Documenting**: Interactive schema exploration
- **Flexible**: Request only needed fields, reduce over-fetching

### For Business Users
- **Natural Language**: Ask questions in plain English
- **Intelligent Responses**: Context-aware analysis with expert knowledge
- **Actionable Insights**: Specific recommendations with prioritization
- **Real-time Updates**: Live monitoring of compliance status

### For Executives
- **Strategic View**: High-level compliance metrics and trends
- **Risk Assessment**: Data-driven risk analysis with business context
- **Decision Support**: AI-powered recommendations for resource allocation
- **Regulatory Compliance**: Framework-specific guidance (SOX, HIPAA, PCI-DSS)

## 📈 Performance & Scalability

- **GraphQL**: Efficient single-request data fetching
- **Caching**: Built-in caching for lifecycle data and query results
- **Async Operations**: Non-blocking database and API calls
- **Rate Limiting**: Production-ready throttling and circuit breakers
- **Vector Store**: Optimized semantic search for compliance knowledge

## 🔐 Security & Compliance

- **API Security**: CORS, input validation, error handling
- **Data Privacy**: No sensitive data in logs or vector stores
- **Audit Trail**: Complete request/response logging
- **Access Control**: Ready for enterprise authentication integration

---

**Repository**: https://github.com/ashzak/servicenow-compliance-scanner

This represents a significant evolution from basic compliance scanning to enterprise-grade AI-powered compliance intelligence with flexible API access.