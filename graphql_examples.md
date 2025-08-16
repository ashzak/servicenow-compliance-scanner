# GraphQL API Examples - Enterprise CMDB Compliance Tool

## 🚀 GraphQL Endpoint
**URL**: http://localhost:8001/graphql
**GraphQL Playground**: http://localhost:8001/graphql (GET request for interactive UI)

## 📊 Query Examples

### 1. Get Compliance Summary
```graphql
query ComplianceDashboard {
  complianceSummary {
    totalSystems
    compliantSystems
    warningSystems
    criticalSystems
    complianceScore
    avgRiskScore
    lastUpdated
  }
}
```

### 2. Get Compliance Findings with Filters
```graphql
query CriticalFindings {
  complianceFindings(
    filter: { 
      status: FAIL 
      minRiskScore: 80 
    }
    limit: 10
  ) {
    id
    status
    reason
    riskScore
    evaluatedAt
    ci {
      name
      businessUnit
      ipAddress
      ciClass
    }
    osFacts {
      product
      version
      connectorUsed
    }
  }
}
```

### 3. Business Unit Risk Analysis
```graphql
query BusinessUnitAnalysis {
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
}
```

### 4. Network Device Compliance
```graphql
query NetworkDevices {
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
      edition
    }
  }
}
```

### 5. Get Specific CI Details
```graphql
query CIDetails($ciId: String!) {
  ci(id: $ciId) {
    name
    ciClass
    businessUnit
    owner
    ipAddress
    location
    environment
    criticality
    tags
  }
}
```

### 6. Recently Evaluated Systems
```graphql
query RecentEvaluations {
  complianceFindings(
    limit: 20
  ) {
    ci {
      name
      businessUnit
    }
    status
    reason
    riskScore
    evaluatedAt
    remediation
  }
}
```

## 🔧 Mutation Examples

### 1. Start Compliance Scan
```graphql
mutation StartScan {
  startComplianceScan(
    businessUnit: "Finance"
  ) {
    scanId
    status
    progress
    totalSystems
    startedAt
  }
}
```

### 2. Start Targeted Scan
```graphql
mutation StartTargetedScan {
  startComplianceScan(
    ciIds: ["ci_001", "ci_002", "ci_003"]
  ) {
    scanId
    status
    progress
    totalSystems
    estimatedCompletion
  }
}
```

## 📡 Subscription Examples

### 1. Real-time Compliance Updates
```graphql
subscription ComplianceAlerts {
  complianceUpdates {
    id
    ciId
    status
    reason
    riskScore
    evaluatedAt
    ci {
      name
      businessUnit
    }
  }
}
```

## 🏢 Enterprise Use Cases

### Executive Dashboard Query
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
  criticalFindings: complianceFindings(
    filter: { status: FAIL }
    limit: 5
  ) {
    ci { name, businessUnit }
    reason
    riskScore
  }
}
```

### Security Team Query
```graphql
query SecurityDashboard {
  highRiskSystems: complianceFindings(
    filter: { 
      status: FAIL
      minRiskScore: 85 
    }
  ) {
    ci {
      name
      businessUnit
      ipAddress
      criticality
    }
    reason
    riskScore
    remediation
    evaluatedAt
  }
  
  businessUnits {
    name
    criticalCount
    avgRiskScore
  }
}
```

### Operations Team Query
```graphql
query OperationsDashboard {
  systemsNeedingAttention: complianceFindings(
    filter: { 
      status: WARN
    }
  ) {
    ci {
      name
      owner
      businessUnit
    }
    reason
    remediation
    evaluatedAt
  }
  
  recentScans: complianceFindings(
    limit: 10
  ) {
    ci { name }
    status
    evaluatedAt
  }
}
```

## 🔍 Advanced Filtering Examples

### Filter by Date Range (Future Enhancement)
```graphql
query RecentFindings {
  complianceFindings(
    filter: {
      daysSinceScan: 7
      status: FAIL
    }
    limit: 50
  ) {
    ci { name, businessUnit }
    status
    reason
    evaluatedAt
  }
}
```

### Filter by Risk Score Range
```graphql
query MediumRiskSystems {
  complianceFindings(
    filter: {
      minRiskScore: 40
      maxRiskScore: 79
    }
  ) {
    ci { name, businessUnit }
    riskScore
    reason
    remediation
  }
}
```

## 🎯 Benefits of GraphQL API

1. **Single Request**: Get complex nested data in one query
2. **Precise Data**: Request only the fields you need
3. **Strong Typing**: Built-in validation and documentation
4. **Real-time**: Subscription support for live updates
5. **Introspection**: Self-documenting API schema
6. **Flexible**: Adapt queries to different client needs

## 🌐 Testing GraphQL

### Using curl:
```bash
curl -X POST http://localhost:8001/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query { complianceSummary { totalSystems complianceScore } }"}'
```

### Using GraphQL Playground:
1. Open http://localhost:8001/graphql in browser
2. Interactive query editor with auto-completion
3. Schema documentation on the right
4. Query validation and formatting

The GraphQL API provides powerful, flexible access to all compliance data with enterprise-grade performance and security.