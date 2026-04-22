#!/usr/bin/env python3
"""
Gemini API Verification Module

Verifies domains as phishing or legitimate using Google's Gemini API.
Provides ground-truth labels for dataset training.

Usage:
    from modules.gemini_verification import GeminiDomainVerifier
    
    verifier = GeminiDomainVerifier(api_key="your-api-key")
    result = verifier.verify_domain("example.com")
    print(result.is_phishing)  # True or False
    print(result.confidence)   # 0.0-1.0
"""

import logging
from dataclasses import dataclass
from typing import Optional
import time
import os

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result from Gemini domain verification"""
    domain: str
    is_phishing: bool
    confidence: float  # 0.0-1.0
    reasoning: str
    source: str = "gemini"
    
    def __str__(self):
        label = "PHISHING" if self.is_phishing else "LEGITIMATE"
        return f"{self.domain:40} | {label:10} | Conf: {self.confidence:.2%} | {self.reasoning[:50]}"


class GeminiDomainVerifier:
    """Verify domains using Google Gemini API"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Gemini verifier
        
        Args:
            api_key: Gemini API key (from environment variable GEMINI_API_KEY if not provided)
        """
        if not GEMINI_AVAILABLE:
            logger.warning("⚠️  Gemini API not available - install with: pip install google-generativeai")
            self.model = None
            return
        
        # Get API key from parameter or environment
        key = api_key or os.getenv("GEMINI_API_KEY")
        
        if not key:
            logger.error(
                "❌ Gemini API key not found. Set GEMINI_API_KEY environment variable:\n"
                "   export GEMINI_API_KEY='your-api-key'\n"
                "   Get key from: https://ai.google.dev/"
            )
            self.model = None
            self.initialized = False
            return
        
        try:
            genai.configure(api_key=key)
            # Use gemini-2.5-flash - latest and fastest model
            self.model = genai.GenerativeModel("gemini-2.5-flash")
            self.initialized = True
            logger.info("✅ Gemini API initialized successfully (gemini-2.5-flash)")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Gemini: {e}")
            self.model = None
            self.initialized = False
    
    def verify_domain(
        self,
        domain: str,
        timeout: int = 10,
        retry_count: int = 3
    ) -> VerificationResult:
        """
        Verify if domain is phishing or legitimate using Gemini
        
        Args:
            domain: Domain name to verify
            timeout: Timeout in seconds
            retry_count: Number of retries on failure
            
        Returns:
            VerificationResult with phishing status and confidence
        """
        if not self.initialized or not self.model:
            return self._fallback_verification(domain)
        
        # Construct verification prompt
        prompt = f"""Analyze if "{domain}" is a phishing domain or legitimate website.

Consider:
1. Domain name similarities to popular services
2. Suspicious patterns (e.g., domains with extra characters, numbers)
3. Common phishing target types (PayPal, Amazon, Apple, Microsoft, banks)
4. Known phishing indicators (misspellings, unusual TLDs)

Respond in JSON format ONLY:
{{
  "is_phishing": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation"
}}

Domain: {domain}"""

        for attempt in range(retry_count):
            try:
                # Call Gemini API
                response = self.model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,  # Low temperature for deterministic results
                        max_output_tokens=200,
                    )
                )
                
                # Parse response
                result_text = response.text.strip()
                
                # Extract JSON
                try:
                    import json
                    
                    # Try to find JSON in response
                    start_idx = result_text.find('{')
                    end_idx = result_text.rfind('}') + 1
                    
                    if start_idx >= 0 and end_idx > start_idx:
                        json_str = result_text[start_idx:end_idx]
                        data = json.loads(json_str)
                        
                        return VerificationResult(
                            domain=domain,
                            is_phishing=data.get("is_phishing", False),
                            confidence=float(data.get("confidence", 0.5)),
                            reasoning=data.get("reasoning", "Verified by Gemini")
                        )
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Failed to parse Gemini response: {e}")
                    # Try to extract yes/no from text
                    return self._parse_text_response(domain, result_text)
                    
            except Exception as e:
                if attempt < retry_count - 1:
                    logger.warning(f"Attempt {attempt+1} failed: {e}. Retrying...")
                    time.sleep(1)  # Wait before retry
                else:
                    logger.error(f"All verification attempts failed for {domain}: {e}")
                    return self._fallback_verification(domain)
        
        return self._fallback_verification(domain)
    
    def _parse_text_response(self, domain: str, text: str) -> VerificationResult:
        """Parse text response to extract phishing status"""
        text_lower = text.lower()
        
        # Look for indicators
        phishing_indicators = ["phishing", "malicious", "suspicious", "fake"]
        legit_indicators = ["legitimate", "safe", "authentic", "not phishing"]
        
        is_phishing = False
        for indicator in phishing_indicators:
            if indicator in text_lower:
                is_phishing = True
                break
        
        if not is_phishing:
            for indicator in legit_indicators:
                if indicator in text_lower:
                    is_phishing = False
                    break
        
        confidence = 0.7 if any(ind in text_lower for ind in phishing_indicators + legit_indicators) else 0.5
        
        return VerificationResult(
            domain=domain,
            is_phishing=is_phishing,
            confidence=confidence,
            reasoning=text[:100]  # First 100 chars of response
        )
    
    def _fallback_verification(self, domain: str) -> VerificationResult:
        """Fallback verification using heuristics when Gemini unavailable"""
        logger.warning(f"⚠️  Using fallback verification for {domain}")
        
        # Phishing patterns with confidence weights
        strong_phishing = ["verify", "confirm", "login", "signin", "update", "secure"]
        medium_phishing = ["account", "alert", "urgent", "warning", "check", "click"]
        weak_phishing = ["-", "0", "1"]
        brand_names = ["paypal", "amazon", "apple", "microsoft", "google", "bank", "chase"]
        
        domain_lower = domain.lower()
        confidence = 0.5  # Base confidence
        
        # Count indicators
        strong_count = sum(1 for p in strong_phishing if p in domain_lower)
        medium_count = sum(1 for p in medium_phishing if p in domain_lower)
        weak_count = sum(1 for p in weak_phishing if p in domain_lower)
        brand_count = sum(1 for b in brand_names if b in domain_lower)
        
        # Calculate phishing probability
        phishing_score = (strong_count * 0.4) + (medium_count * 0.2) + (weak_count * 0.1) + (brand_count * 0.3)
        
        if phishing_score > 0.5:
            is_phishing = True
            confidence = min(0.95, 0.5 + (phishing_score * 0.4))  # 0.5-0.95 range
        else:
            is_phishing = False
            confidence = min(0.9, 0.5 + (1 - phishing_score) * 0.3)  # 0.5-0.8 range
        
        return VerificationResult(
            domain=domain,
            is_phishing=is_phishing,
            confidence=confidence,
            reasoning="Fallback heuristic (Gemini unavailable)"
        )
    
    def verify_batch(self, domains: list, verbose: bool = True) -> list:
        """
        Verify multiple domains
        
        Args:
            domains: List of domain names
            verbose: Print progress
            
        Returns:
            List of VerificationResults
        """
        results = []
        for i, domain in enumerate(domains, 1):
            if verbose:
                print(f"[{i}/{len(domains)}] Verifying {domain}...", end=" ", flush=True)
            
            result = self.verify_domain(domain)
            results.append(result)
            
            if verbose:
                status = "🚨 PHISHING" if result.is_phishing else "✅ LEGIT"
                print(f"{status} ({result.confidence:.0%})")
            
            # Rate limiting
            time.sleep(0.5)
        
        return results


def get_verifier(api_key: Optional[str] = None) -> GeminiDomainVerifier:
    """Get initialized Gemini verifier"""
    return GeminiDomainVerifier(api_key)


if __name__ == "__main__":
    # Example usage
    verifier = get_verifier()
    
    # Test domains
    test_domains = [
        "google.com",
        "amazon.com",
        "paypal-verify.com",
        "apple-security-login.com",
    ]
    
    print("\n" + "="*80)
    print("GEMINI DOMAIN VERIFICATION TEST")
    print("="*80 + "\n")
    
    results = verifier.verify_batch(test_domains)
    
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    for result in results:
        print(result)
    
    # Statistics
    phishing_count = sum(1 for r in results if r.is_phishing)
    print(f"\nPhishing: {phishing_count}/{len(results)}")
    print(f"Legitimate: {len(results) - phishing_count}/{len(results)}")
