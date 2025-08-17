#!/usr/bin/env python3
"""
Microsoft Copilot API Client for Enterprise CMDB Compliance Tool
Provides Copilot integration as alternative to OpenAI
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
import aiohttp
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CopilotConfig:
    """Configuration for Copilot API client"""
    api_key: str
    endpoint: str = "https://api.github.com/copilot/chat/completions"
    model: str = "gpt-4"
    max_tokens: int = 1000
    temperature: float = 0.3
    timeout: int = 30

class CopilotAPIClient:
    """Microsoft Copilot API client compatible with OpenAI interface"""
    
    def __init__(self, config: CopilotConfig):
        self.config = config
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ServiceNow-Compliance-Tool/1.0"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def chat_completion(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> Dict[str, Any]:
        """Create chat completion using Copilot API"""
        
        payload = {
            "model": kwargs.get("model", self.config.model),
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": False
        }
        
        try:
            async with self.session.post(self.config.endpoint, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return result
                else:
                    error_text = await response.text()
                    logger.error(f"Copilot API error {response.status}: {error_text}")
                    raise Exception(f"Copilot API error {response.status}: {error_text}")
                    
        except Exception as e:
            logger.error(f"Copilot API request failed: {e}")
            raise

class AsyncCopilot:
    """OpenAI-compatible async client for Copilot"""
    
    def __init__(self, api_key: str, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url or "https://api.github.com/copilot"
        self.config = CopilotConfig(
            api_key=api_key,
            endpoint=f"{self.base_url}/chat/completions"
        )
        
    @property
    def chat(self):
        """Chat completions interface"""
        return CopilotChatCompletions(self.config)

class CopilotChatCompletions:
    """Chat completions interface for Copilot"""
    
    def __init__(self, config: CopilotConfig):
        self.config = config
    
    async def create(
        self, 
        model: str = "gpt-4",
        messages: List[Dict[str, str]] = None,
        temperature: float = 0.3,
        max_tokens: int = 1000,
        **kwargs
    ) -> 'CopilotResponse':
        """Create chat completion"""
        
        async with CopilotAPIClient(self.config) as client:
            result = await client.chat_completion(
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            
            return CopilotResponse(result)

class CopilotResponse:
    """Copilot response wrapper compatible with OpenAI format"""
    
    def __init__(self, response_data: Dict[str, Any]):
        self.data = response_data
        self.choices = [CopilotChoice(choice) for choice in response_data.get("choices", [])]

class CopilotChoice:
    """Copilot choice wrapper"""
    
    def __init__(self, choice_data: Dict[str, Any]):
        self.data = choice_data
        self.message = CopilotMessage(choice_data.get("message", {}))

class CopilotMessage:
    """Copilot message wrapper"""
    
    def __init__(self, message_data: Dict[str, Any]):
        self.data = message_data
        self.content = message_data.get("content", "")
        self.role = message_data.get("role", "assistant")

# Fallback implementations for when Copilot API is not available
class MockCopilotClient:
    """Mock Copilot client for testing and fallback"""
    
    def __init__(self, api_key: str = "mock", base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url
        logger.info("Using mock Copilot client (API not configured)")
    
    @property
    def chat(self):
        return MockCopilotChatCompletions()

class MockCopilotChatCompletions:
    """Mock chat completions for Copilot"""
    
    async def create(self, **kwargs):
        """Return mock response"""
        messages = kwargs.get("messages", [])
        user_message = ""
        
        for msg in messages:
            if msg.get("role") == "user":
                user_message = msg.get("content", "")
                break
        
        # Generate contextual mock responses
        if "compliance" in user_message.lower():
            mock_content = "Based on the compliance analysis, I recommend focusing on EOL systems and critical vulnerabilities. This is a mock response from the Copilot fallback client."
        elif "critical" in user_message.lower():
            mock_content = "Critical systems require immediate attention. Please review the risk scores and prioritize remediation. This is a mock response from the Copilot fallback client."
        elif "summary" in user_message.lower():
            mock_content = "Compliance Summary: The system shows various compliance findings across different business units. This is a mock response from the Copilot fallback client."
        else:
            mock_content = f"I understand your question about: {user_message[:50]}... This is a mock response from the Copilot fallback client while the real API is not configured."
        
        return MockCopilotResponse(mock_content)

class MockCopilotResponse:
    """Mock response wrapper"""
    
    def __init__(self, content: str):
        self.choices = [MockCopilotChoice(content)]

class MockCopilotChoice:
    """Mock choice wrapper"""
    
    def __init__(self, content: str):
        self.message = MockCopilotMessage(content)

class MockCopilotMessage:
    """Mock message wrapper"""
    
    def __init__(self, content: str):
        self.content = content.strip()

# Factory function to create appropriate client
def create_copilot_client(api_key: Optional[str] = None, base_url: Optional[str] = None) -> AsyncCopilot:
    """Factory function to create Copilot client with fallback"""
    
    # Try to get API key from environment if not provided
    if not api_key:
        api_key = os.getenv("COPILOT_API_KEY") or os.getenv("GITHUB_TOKEN")
    
    if api_key and api_key != "mock" and api_key != "demo-key":
        try:
            return AsyncCopilot(api_key=api_key, base_url=base_url)
        except Exception as e:
            logger.warning(f"Failed to create Copilot client: {e}")
            return MockCopilotClient()
    else:
        logger.info("No Copilot API key configured, using mock client")
        return MockCopilotClient()

# Test function
async def test_copilot_client():
    """Test Copilot client functionality"""
    
    print("🤖 Testing Microsoft Copilot API Client")
    print("=" * 50)
    
    # Test with mock client
    client = create_copilot_client("mock")
    
    test_messages = [
        {"role": "system", "content": "You are a compliance expert."},
        {"role": "user", "content": "What are the critical compliance issues I should focus on?"}
    ]
    
    try:
        response = await client.chat.completions.create(
            model="gpt-4",
            messages=test_messages,
            temperature=0.3
        )
        
        print(f"✅ Response: {response.choices[0].message.content}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("💡 To use real Copilot API:")
    print("   export COPILOT_API_KEY='your-github-token'")
    print("   or")
    print("   export GITHUB_TOKEN='your-github-token'")

if __name__ == "__main__":
    asyncio.run(test_copilot_client())