#!/usr/bin/env python3
"""
Test Enhanced LLM Assistant with GraphQL Orchestration
Demonstrates the hybrid approach of GraphQL queries + RAG
"""

import asyncio
import json
import os
from llm_assistant import ComplianceAssistant

async def test_enhanced_llm():
    """Test the enhanced LLM assistant with GraphQL orchestration"""
    
    print("🚀 Testing Enhanced LLM Assistant with GraphQL Orchestration + RAG")
    print("=" * 80)
    
    # Configure assistant with your OpenAI API key
    config = {
        "llm": {
            "api_key": os.getenv("OPENAI_API_KEY", "demo-key")
        },
        "graphql_endpoint": "http://localhost:8001/graphql",
        "vector_db": {
            "persist_directory": "./compliance_chroma_db"
        }
    }
    
    # Initialize assistant
    assistant = ComplianceAssistant(config)
    
    print(f"✅ Assistant initialized")
    print(f"   - GraphQL Orchestrator: {'✅' if assistant.graphql_orchestrator else '❌'}")
    print(f"   - OpenAI Available: {'✅' if hasattr(assistant.llm_client, 'chat') else '❌'}")
    print(f"   - Vector Store: {'✅' if assistant.vector_db else '❌'}")
    print()
    
    # Test questions that should use different methods
    test_cases = [
        {
            "question": "Show me the overall compliance summary",
            "expected_method": "graphql_orchestration",
            "category": "Data Query - Dashboard"
        },
        {
            "question": "What are the critical systems in Finance?", 
            "expected_method": "graphql_orchestration",
            "category": "Data Query - Filtered Search"
        },
        {
            "question": "Which network devices have compliance issues?",
            "expected_method": "graphql_orchestration", 
            "category": "Data Query - Asset Type"
        },
        {
            "question": "What is SOX compliance and why is it important?",
            "expected_method": "traditional_rag",
            "category": "Knowledge Query - Concepts"
        },
        {
            "question": "Explain best practices for EOL management",
            "expected_method": "traditional_rag",
            "category": "Knowledge Query - Best Practices"
        },
        {
            "question": "How should I prioritize fixing my failing systems?",
            "expected_method": "graphql_orchestration",  # Hybrid - gets data + knowledge
            "category": "Hybrid Query - Analysis + Advice"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"🧪 Test {i}: {test_case['category']}")
        print(f"   Question: \"{test_case['question']}\"")
        
        try:
            # Ask the question
            result = await assistant.ask_question(test_case["question"])
            
            # Display results
            method_used = result.get("method", "unknown")
            print(f"   Method Used: {method_used}")
            print(f"   Expected: {test_case['expected_method']}")
            print(f"   Match: {'✅' if method_used == test_case['expected_method'] else '❌'}")
            
            if result.get("graphql_query"):
                print(f"   GraphQL Query: {result['graphql_query'][:60]}...")
            
            if result.get("sources"):
                print(f"   RAG Sources: {len(result['sources'])} documents")
            
            print(f"   Answer: {result['answer'][:100]}...")
            print(f"   Confidence: {result.get('confidence', 'N/A')}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print("-" * 80)
        
        # Small delay between tests
        await asyncio.sleep(1)
    
    print("\n🎯 Testing Real-time GraphQL + RAG Integration")
    print("=" * 80)
    
    # Test with live GraphQL endpoint
    live_test_questions = [
        "How many systems do we have total?",
        "Show me systems with risk scores above 80", 
        "What's our current compliance percentage?"
    ]
    
    for question in live_test_questions:
        print(f"📊 Live Test: \"{question}\"")
        
        try:
            result = await assistant.ask_question(question)
            
            print(f"   Method: {result.get('method', 'unknown')}")
            print(f"   Answer: {result['answer']}")
            
            if result.get("data"):
                print(f"   Data Retrieved: {len(str(result['data']))} chars")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print("-" * 40)
    
    print("\n✅ Enhanced LLM Assistant Testing Complete!")
    print("\nKey Features Demonstrated:")
    print("🔍 Intelligent query routing (GraphQL vs RAG)")
    print("📊 Live data retrieval via GraphQL orchestration") 
    print("📚 Knowledge-based responses via RAG")
    print("🤖 LLM-powered query generation and analysis")
    print("🔄 Hybrid approach combining data + knowledge")

if __name__ == "__main__":
    asyncio.run(test_enhanced_llm())