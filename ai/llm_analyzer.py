#!/usr/bin/env python3
"""
VIPER LLM Analyzer - AI-Powered Security Analysis

Integration with VIPER primary agent for:
- Analyzing interesting findings
- Deciding next attack vectors
- Triaging false positives
- Generating exploit strategies
"""

import asyncio
import logging

logger = logging.getLogger("viper.llm_analyzer")
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

HACKAGENT_DIR = Path(__file__).parent.parent
AI_OUTPUT_DIR = HACKAGENT_DIR / "data" / "ai"
AI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Queue file for async communication with main agent
ANALYSIS_QUEUE_FILE = HACKAGENT_DIR / "core" / "analysis_queue.json"
ANALYSIS_RESULTS_FILE = HACKAGENT_DIR / "core" / "analysis_results.json"


@dataclass
class AnalysisRequest:
    """Request for LLM analysis"""
    request_id: str
    request_type: str  # 'triage', 'strategy', 'exploit', 'next_vector'
    target: str
    context: Dict[str, Any]
    priority: int = 1  # 1=normal, 2=high, 3=critical
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "request_type": self.request_type,
            "target": self.target,
            "context": self.context,
            "priority": self.priority,
            "timestamp": self.timestamp
        }


@dataclass
class AnalysisResult:
    """Result from LLM analysis"""
    request_id: str
    analysis: str
    recommendations: List[str]
    next_attacks: List[str]
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "analysis": self.analysis,
            "recommendations": self.recommendations,
            "next_attacks": self.next_attacks,
            "confidence": self.confidence,
            "timestamp": self.timestamp
        }


class LLMAnalyzer:
    """
    LLM-based security analysis integration.
    
    Can operate in two modes:
    1. Direct API calls (if API key available)
    2. Queue-based async communication with main agent
    
    The main agent processes the queue during heartbeats
    and provides analysis results.
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.request_counter = 0
        
        # Check for direct API access
        self.anthropic_key = os.environ.get('ANTHROPIC_API_KEY')
        self.openai_key = os.environ.get('OPENAI_API_KEY')
        
        self._ensure_files()
    
    def log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [LLM] [{level}] {msg}")
    
    def _ensure_files(self):
        """Ensure queue files exist"""
        if not ANALYSIS_QUEUE_FILE.exists():
            ANALYSIS_QUEUE_FILE.write_text("[]")
        if not ANALYSIS_RESULTS_FILE.exists():
            ANALYSIS_RESULTS_FILE.write_text("{}")
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        self.request_counter += 1
        return f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.request_counter}"
    
    async def request_analysis(self, request_type: str, target: str, 
                                context: Dict[str, Any],
                                priority: int = 1) -> str:
        """
        Submit analysis request.
        
        Args:
            request_type: Type of analysis ('triage', 'strategy', 'exploit', 'next_vector')
            target: Target URL/domain
            context: Relevant context (findings, technologies, etc.)
            priority: 1=normal, 2=high, 3=critical
        
        Returns:
            request_id for tracking
        """
        request = AnalysisRequest(
            request_id=self._generate_request_id(),
            request_type=request_type,
            target=target,
            context=context,
            priority=priority
        )
        
        # Add to queue
        queue = self._load_queue()
        queue.append(request.to_dict())
        self._save_queue(queue)
        
        self.log(f"Queued {request_type} analysis for {target} (ID: {request.request_id})")
        
        return request.request_id
    
    def _load_queue(self) -> List[Dict]:
        """Load analysis queue"""
        try:
            return json.loads(ANALYSIS_QUEUE_FILE.read_text())
        except Exception as e:  # noqa: BLE001
            return []
    
    def _save_queue(self, queue: List[Dict]):
        """Save analysis queue"""
        ANALYSIS_QUEUE_FILE.write_text(json.dumps(queue, indent=2))
    
    def _load_results(self) -> Dict[str, Dict]:
        """Load analysis results"""
        try:
            return json.loads(ANALYSIS_RESULTS_FILE.read_text())
        except Exception as e:  # noqa: BLE001
            return {}
    
    def _save_results(self, results: Dict[str, Dict]):
        """Save analysis results"""
        ANALYSIS_RESULTS_FILE.write_text(json.dumps(results, indent=2))
    
    async def get_result(self, request_id: str, 
                          timeout: int = 60) -> Optional[AnalysisResult]:
        """
        Wait for and retrieve analysis result.
        
        Args:
            request_id: ID from request_analysis
            timeout: Max seconds to wait
        """
        start = datetime.now()
        
        while (datetime.now() - start).total_seconds() < timeout:
            results = self._load_results()
            if request_id in results:
                data = results[request_id]
                return AnalysisResult(
                    request_id=request_id,
                    analysis=data.get('analysis', ''),
                    recommendations=data.get('recommendations', []),
                    next_attacks=data.get('next_attacks', []),
                    confidence=data.get('confidence', 0.0)
                )
            
            await asyncio.sleep(2)
        
        return None
    
    async def triage_finding(self, finding: Dict, target: str) -> str:
        """
        Submit a finding for triage analysis.
        
        Asks the LLM to assess:
        - Is this a true positive?
        - What's the severity?
        - What's the impact?
        """
        context = {
            "finding": finding,
            "question": "Analyze this security finding. Is it a true positive? What is the actual severity and potential impact?"
        }
        
        return await self.request_analysis(
            request_type="triage",
            target=target,
            context=context,
            priority=2 if finding.get('severity', '').lower() in ['critical', 'high'] else 1
        )
    
    async def get_next_vectors(self, target: str, 
                                technologies: List[str],
                                findings: List[Dict],
                                tried_attacks: List[str]) -> str:
        """
        Ask LLM for next attack vector recommendations.
        
        Provides context about what we've found and tried,
        and asks for recommendations on what to try next.
        """
        context = {
            "technologies": technologies,
            "findings": findings[:10],  # Limit to avoid token overflow
            "tried_attacks": tried_attacks,
            "question": "Based on the technologies and findings, what attack vectors should be tried next? Consider what hasn't been tried yet and what might be effective."
        }
        
        return await self.request_analysis(
            request_type="next_vector",
            target=target,
            context=context,
            priority=1
        )
    
    async def generate_exploit_strategy(self, finding: Dict, 
                                          target: str) -> str:
        """
        Ask LLM to generate exploitation strategy.
        
        For a confirmed vulnerability, get step-by-step
        exploitation guidance.
        """
        context = {
            "finding": finding,
            "question": "Generate a step-by-step exploitation strategy for this vulnerability. Include specific payloads and techniques."
        }
        
        return await self.request_analysis(
            request_type="exploit",
            target=target,
            context=context,
            priority=3
        )
    
    async def analyze_response(self, url: str, 
                                 status: int, 
                                 body: str, 
                                 headers: Dict) -> str:
        """
        Ask LLM to analyze HTTP response for vulnerabilities.
        
        Useful for identifying subtle issues that pattern matching misses.
        """
        # Truncate body to avoid token limits
        body_truncated = body[:5000] if len(body) > 5000 else body
        
        context = {
            "url": url,
            "status": status,
            "headers": dict(list(headers.items())[:20]),  # Limit headers
            "body_preview": body_truncated,
            "question": "Analyze this HTTP response for security vulnerabilities, misconfigurations, or information leaks. Focus on actionable findings."
        }
        
        return await self.request_analysis(
            request_type="triage",
            target=url,
            context=context,
            priority=1
        )
    
    # =====================
    # Queue Processing (for main agent)
    # =====================
    
    def get_pending_requests(self) -> List[Dict]:
        """Get pending analysis requests (for main agent to process)"""
        return self._load_queue()
    
    def submit_result(self, request_id: str, 
                       analysis: str,
                       recommendations: List[str] = None,
                       next_attacks: List[str] = None,
                       confidence: float = 0.8):
        """
        Submit analysis result (called by main agent).
        
        Args:
            request_id: Request ID being answered
            analysis: Analysis text
            recommendations: List of recommendations
            next_attacks: Suggested attacks
            confidence: Confidence level 0-1
        """
        results = self._load_results()
        results[request_id] = {
            "analysis": analysis,
            "recommendations": recommendations or [],
            "next_attacks": next_attacks or [],
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        }
        self._save_results(results)
        
        # Remove from queue
        queue = self._load_queue()
        queue = [r for r in queue if r.get('request_id') != request_id]
        self._save_queue(queue)
        
        self.log(f"Result submitted for {request_id}")
    
    def clear_old_requests(self, max_age_hours: int = 24):
        """Clear old requests from queue"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        queue = self._load_queue()
        
        new_queue = []
        for req in queue:
            try:
                req_time = datetime.fromisoformat(req.get('timestamp', ''))
                if req_time > cutoff:
                    new_queue.append(req)
            except Exception as e:  # noqa: BLE001
                pass
        
        self._save_queue(new_queue)
        self.log(f"Cleared {len(queue) - len(new_queue)} old requests")
    
    # =====================
    # API Key Discovery
    # =====================

    def _find_api_key(self) -> Optional[str]:
        """Find Anthropic API key from environment."""
        return os.environ.get('ANTHROPIC_API_KEY')

    # =====================
    # Direct Analysis (if API available)
    # =====================

    async def _call_claude(self, system: str, user: str, max_tokens: int = 1024) -> Optional[str]:
        """Direct Claude API call via urllib (no external deps)."""
        key = self.anthropic_key or self._find_api_key()
        if not key:
            return None

        import urllib.request
        import urllib.error

        body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode()

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
                return data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            self.log(f"Claude API HTTP error: {e.code}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Claude API error: {e}", "ERROR")
            return None

    @property
    def has_direct_api(self) -> bool:
        """Check if direct API is available."""
        return bool(self.anthropic_key or self._find_api_key())

    async def direct_analyze(self, prompt: str,
                              system_prompt: str = None) -> Optional[str]:
        """
        Direct LLM analysis using available API.

        Falls back to queue-based if no API available.
        """
        result = await self._call_claude(
            system=system_prompt or "You are a security researcher analyzing web application vulnerabilities. Be concise and actionable.",
            user=prompt,
        )
        if result:
            return result
        if self.openai_key:
            return await self._call_openai(prompt, system_prompt)
        self.log("No direct API available, using queue-based analysis", "WARN")
        return None

    async def _call_anthropic(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Call Anthropic Claude API (legacy wrapper)."""
        return await self._call_claude(
            system=system_prompt or "You are a security researcher.",
            user=prompt,
        )

    async def _call_openai(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Call OpenAI API"""
        try:
            import openai

            client = openai.OpenAI(api_key=self.openai_key)

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                max_tokens=2000
            )

            return response.choices[0].message.content
        except Exception as e:
            self.log(f"OpenAI API error: {e}", "ERROR")
            return None

    # =====================
    # High-Level Security Analysis Methods
    # =====================

    async def analyze_response_for_vulns(self, url: str, status: int,
                                          body: str, headers: Dict) -> Optional[Dict]:
        """LLM analyzes an HTTP response for security issues."""
        system = (
            "You are a bug bounty expert. Analyze HTTP responses for security vulnerabilities. "
            "Be precise — only report real, exploitable issues. Output valid JSON only."
        )
        user = (
            f"URL: {url}\nStatus: {status}\n"
            f"Headers: {json.dumps(dict(list(headers.items())[:15]))}\n"
            f"Body (first 3000 chars): {body[:3000]}\n\n"
            "Identify any security vulnerabilities, misconfigurations, or information leaks. "
            "For each, provide: type, severity (critical/high/medium/low/info), evidence, confidence (0-1). "
            'Output JSON array: [{"type":"...","severity":"...","evidence":"...","confidence":0.0}]'
        )
        result = await self._call_claude(system, user)
        if result:
            try:
                # Try to extract JSON from response
                import re
                match = re.search(r'\[.*\]', result, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except (json.JSONDecodeError, AttributeError):
                pass
        return None

    async def decide_next_attack(self, target_info: Dict,
                                   attack_history: List,
                                   findings: List) -> List[str]:
        """LLM decides what attacks to try next."""
        system = (
            "You are an expert penetration tester. Given target context, recommend specific "
            "attack vectors to try next. Output a JSON array of attack type strings."
        )
        user = (
            f"Target: {json.dumps(target_info, default=str)[:2000]}\n"
            f"Previous attacks tried: {json.dumps(attack_history[-20:], default=str)[:1000]}\n"
            f"Findings so far: {json.dumps(findings[:10], default=str)[:1000]}\n\n"
            "What attack vectors should be tried next? Consider the tech stack and what hasn't been tried. "
            'Output JSON array of strings: ["sqli", "ssti", ...]'
        )
        result = await self._call_claude(system, user, max_tokens=512)
        if result:
            try:
                import re
                match = re.search(r'\[.*?\]', result, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except (json.JSONDecodeError, AttributeError):
                pass
        return []

    async def generate_contextual_payloads(self, vuln_type: str,
                                             tech_stack: List[str],
                                             waf: str = None) -> List[str]:
        """LLM generates payloads customized for the target's tech stack and WAF."""
        system = (
            "You are a security researcher. Generate testing payloads for authorized penetration testing. "
            "Output only a JSON array of payload strings."
        )
        waf_note = f"\nWAF detected: {waf}. Generate WAF bypass payloads." if waf else ""
        user = (
            f"Vulnerability type: {vuln_type}\n"
            f"Tech stack: {', '.join(tech_stack)}{waf_note}\n\n"
            "Generate 5-10 targeted payloads for this specific tech stack. "
            'Output JSON array: ["payload1", "payload2", ...]'
        )
        result = await self._call_claude(system, user, max_tokens=512)
        if result:
            try:
                import re
                match = re.search(r'\[.*?\]', result, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except (json.JSONDecodeError, AttributeError):
                pass
        return []

    async def triage_finding_direct(self, finding: Dict) -> Optional[Dict]:
        """LLM triages a finding: true positive? severity? impact?"""
        system = (
            "You are a senior bug bounty triager. Assess findings for validity. "
            "Output valid JSON only."
        )
        user = (
            f"Finding: {json.dumps(finding, default=str)[:2000]}\n\n"
            "Assess: Is this a true positive? What's the real severity and impact? "
            'Output JSON: {"is_valid": true/false, "adjusted_severity": "...", '
            '"impact": "...", "reasoning": "..."}'
        )
        result = await self._call_claude(system, user, max_tokens=512)
        if result:
            try:
                import re
                match = re.search(r'\{.*\}', result, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except (json.JSONDecodeError, AttributeError):
                pass
        return None


# =====================
# Helper for main agent
# =====================

def process_viper_analysis_queue():
    """
    Process VIPER analysis queue.
    
    This function is meant to be called by the main agent
    during heartbeats or when checking on VIPER.
    
    Returns a prompt for each pending request that needs analysis.
    """
    analyzer = LLMAnalyzer(verbose=False)
    pending = analyzer.get_pending_requests()
    
    if not pending:
        return None
    
    prompts = []
    for req in pending[:5]:  # Process max 5 at a time
        request_type = req.get('request_type', '')
        target = req.get('target', '')
        context = req.get('context', {})
        
        prompt = f"""VIPER Security Analysis Request
Type: {request_type}
Target: {target}

Context:
{json.dumps(context, indent=2)}

Please provide:
1. Your analysis
2. Specific recommendations (list)
3. Suggested next attacks/vectors (list)
4. Your confidence level (0-1)

Format your response as JSON:
{{
  "analysis": "...",
  "recommendations": ["...", "..."],
  "next_attacks": ["...", "..."],
  "confidence": 0.8
}}
"""
        prompts.append({
            "request_id": req.get('request_id'),
            "prompt": prompt
        })
    
    return prompts


async def main():
    """Demo/test"""
    analyzer = LLMAnalyzer()
    
    # Submit a test request
    req_id = await analyzer.triage_finding(
        finding={
            "type": "sqli",
            "url": "http://test.com/page?id=1'",
            "evidence": "SQL syntax error"
        },
        target="http://test.com"
    )
    
    print(f"Submitted request: {req_id}")
    print(f"Pending requests: {len(analyzer.get_pending_requests())}")


if __name__ == "__main__":
    asyncio.run(main())
