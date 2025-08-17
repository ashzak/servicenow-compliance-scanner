#!/usr/bin/env python3
"""
Test Microsoft Copilot Integration for Enterprise CMDB Compliance Tool
Demonstrates the Copilot-powered compliance assistant capabilities
"""

import asyncio
import json
import os
from llm_assistant import ComplianceAssistant
from copilot_client import test_copilot_client

async def test_copilot_compliance_assistant():
    """Test the Copilot-powered compliance assistant"""
    
    print("🤖 Testing Microsoft Copilot Integration for Compliance Assistant")
    print("=" * 80)
    
    # Test Copilot client first
    print("1️⃣ Testing Copilot API Client...")
    await test_copilot_client()
    print()
    
    # Configure assistant with Copilot
    config = {
        "llm": {
            "provider": "copilot",
            "api_key": os.getenv("COPILOT_API_KEY") or os.getenv("GITHUB_TOKEN", "mock")
        },
        "graphql_endpoint": "http://localhost:8001/graphql",
        "vector_db": {
            "persist_directory": "./compliance_chroma_db"
        }
    }
    
    # Initialize assistant
    assistant = ComplianceAssistant(config)
    
    print("2️⃣ Testing Copilot-Powered Compliance Assistant...")
    print(f"✅ Assistant initialized with provider: {config['llm']['provider']}")
    print(f"   - Copilot Client: {'✅' if hasattr(assistant.llm_client, 'chat') else '❌'}")
    print(f"   - GraphQL Orchestrator: {'✅' if assistant.graphql_orchestrator else '❌'}")
    print(f"   - Vector Store: {'✅' if assistant.vector_db else '❌'}")
    print()
    
    # Test questions specifically for Copilot
    test_cases = [
        {
            "question": "Show me the current compliance dashboard summary",
            "category": "Data Query - Copilot + GraphQL"
        },
        {
            "question": "What are the critical compliance violations in our Finance department?",
            "category": "Business Analysis - Copilot Intelligence"
        },
        {
            "question": "Explain SOX compliance requirements for our organization",
            "category": "Knowledge Query - Copilot + RAG"
        },
        {
            "question": "How should we prioritize remediation for systems with risk scores above 80?",
            "category": "Strategic Advisory - Copilot Reasoning"
        },
        {
            "question": "Which network devices need immediate attention for EOL issues?",
            "category": "Technical Analysis - Copilot + Data"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"🧪 Test {i}: {test_case['category']}")
        print(f"   Question: \"{test_case['question']}\"")
        
        try:
            # Ask the question using Copilot
            result = await assistant.ask_question(test_case["question"])
            
            # Display results
            method_used = result.get("method", "unknown")
            print(f"   Method: {method_used}")
            print(f"   Provider: Microsoft Copilot")
            
            if result.get("graphql_query"):
                print(f"   GraphQL Generated: Yes ({len(result['graphql_query'])} chars)")
            
            if result.get("sources"):
                print(f"   RAG Sources: {len(result['sources'])} documents")
            
            print(f"   Answer Preview: {result['answer'][:120]}...")
            print(f"   Confidence: {result.get('confidence', 'N/A')}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print("-" * 80)
        
        # Small delay between tests
        await asyncio.sleep(1)
    
    print("\n🎯 Testing Copilot vs OpenAI Comparison")
    print("=" * 80)
    
    comparison_question = "What's our biggest compliance risk and how should we address it?"
    
    # Test with Copilot
    print("🤖 Microsoft Copilot Response:")
    try:
        copilot_result = await assistant.ask_question(comparison_question)
        print(f"   Method: {copilot_result.get('method', 'unknown')}")
        print(f"   Answer: {copilot_result['answer'][:200]}...")
    except Exception as e:
        print(f"   ❌ Copilot Error: {e}")
    
    print()
    
    # Test with OpenAI for comparison (if available)
    openai_config = {
        "llm": {
            "provider": "openai",
            "api_key": os.getenv("OPENAI_API_KEY", "mock")
        },
        "graphql_endpoint": "http://localhost:8001/graphql",
        "vector_db": {
            "persist_directory": "./compliance_chroma_db"
        }
    }
    
    print("🔵 OpenAI Response (for comparison):")
    try:
        openai_assistant = ComplianceAssistant(openai_config)
        openai_result = await openai_assistant.ask_question(comparison_question)
        print(f"   Method: {openai_result.get('method', 'unknown')}")
        print(f"   Answer: {openai_result['answer'][:200]}...")
    except Exception as e:
        print(f"   ❌ OpenAI Error: {e}")
    
    print("\n✅ Copilot Integration Testing Complete!")
    print("\nKey Features Demonstrated:")
    print("🤖 Microsoft Copilot API integration")
    print("🔄 Seamless provider switching (Copilot ↔ OpenAI)")
    print("📊 GraphQL query orchestration with Copilot intelligence")
    print("📚 RAG-enhanced responses using Copilot reasoning")
    print("🏢 Enterprise compliance analysis with GitHub's AI")
    
    print("\n💡 Configuration:")
    print("   Set LLM_PROVIDER=copilot to use Microsoft Copilot")
    print("   Set COPILOT_API_KEY or GITHUB_TOKEN for authentication")
    print("   Fallback to OpenAI if Copilot unavailable")

async def test_environment_switching():
    """Test switching between Copilot and OpenAI environments"""
    
    print("\n🔄 Testing Environment Switching")
    print("=" * 50)
    
    providers = [
        {"name": "Microsoft Copilot", "provider": "copilot", "key_env": "COPILOT_API_KEY"},
        {"name": "OpenAI", "provider": "openai", "key_env": "OPENAI_API_KEY"}
    ]
    
    test_question = "How many critical systems do we have?"
    
    for provider_info in providers:
        print(f"\n🧪 Testing {provider_info['name']}:")
        
        config = {
            "llm": {
                "provider": provider_info["provider"],
                "api_key": os.getenv(provider_info["key_env"], "mock")
            },
            "graphql_endpoint": "http://localhost:8001/graphql"
        }
        
        try:
            assistant = ComplianceAssistant(config)
            result = await assistant.ask_question(test_question)
            
            print(f"   ✅ {provider_info['name']} Response:")
            print(f"      Method: {result.get('method', 'unknown')}")
            print(f"      Answer: {result['answer'][:100]}...")
            
        except Exception as e:
            print(f"   ❌ {provider_info['name']} Error: {e}")

if __name__ == "__main__":
    print("🚀 Microsoft Copilot Integration Test Suite")
    print("=" * 60)
    print("Testing enterprise CMDB compliance tool with Copilot AI")
    print()
    
    asyncio.run(test_copilot_compliance_assistant())
    asyncio.run(test_environment_switching())