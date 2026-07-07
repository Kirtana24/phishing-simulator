"""
Phishing Email Detection Engine
Analyzes emails for phishing indicators using pattern matching
Author: Kirtana Minoy
"""

import re
from urllib.parse import urlparse
from typing import Dict, List
import json

class PhishingDetector:
    def __init__(self):
        # Phishing indicators
        self.suspicious_keywords = [
            'urgent', 'immediately', 'asap', 'now', 'quick', 'hurry',
            'suspended', 'locked', 'blocked', 'closed', 'terminated',
            'verify', 'confirm', 'validate', 'secure', 'update',
            'unauthorized', 'suspicious', 'compromised', 'breach',
            'password', 'credit card', 'social security', 'ssn',
            'bank account', 'routing number', 'pin', 'otp'
        ]
        
        self.fake_domains = [
            'chase-bank.secure.com', 'faceb00k-login.com',
            'amaz0n-support.com', 'outlook-servers.net',
            'micros0ft.com', 'g00gle.com', 'paypa1.com'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.pw', '.top',
            '.xyz', '.club', '.online', '.site', '.tech'
        ]
        
        self.generic_greetings = [
            'dear customer', 'dear user', 'dear sir',
            'dear madam', 'hello there'
        ]
        
        self.threat_words = [
            'suspended', 'locked', 'blocked', 'closed',
            'terminated', 'cancelled', 'deactivated'
        ]
        
        self.common_misspellings = [
            'recieve', 'seperate', 'definately', 'occured', 'untill',
            'addres', 'accomodate', 'priviledge', 'maintainance'
        ]

    def analyze_email(self, email_content: str, sender: str = '', subject: str = '') -> Dict:
        """
        Analyze an email for phishing indicators
        
        Returns:
            Dictionary with risk score, red flags, and status
        """
        red_flags = []
        risk_score = 0
        full_content = f"From: {sender}\nSubject: {subject}\n\n{email_content}"

        # 1. Check for urgency keywords
        for keyword in self.suspicious_keywords:
            if keyword.lower() in full_content.lower():
                red_flags.append(f'⚠️ Contains keyword: "{keyword}"')
                risk_score += 8

        # 2. Check sender domain
        if sender:
            for domain in self.fake_domains:
                if domain.lower() in sender.lower():
                    red_flags.append(f'⚠️ Suspicious sender: {domain}')
                    risk_score += 25

        # 3. Check URLs
        urls = self._extract_urls(full_content)
        for url in urls:
            url_analysis = self._analyze_url(url)
            if url_analysis['is_suspicious']:
                red_flags.extend(url_analysis['reasons'])
                risk_score += url_analysis.get('risk_score', 20)

        # 4. Check generic greetings
        for greeting in self.generic_greetings:
            if greeting.lower() in full_content.lower():
                red_flags.append(f'⚠️ Generic greeting: "{greeting}"')
                risk_score += 10

        # 5. Check for threats
        for threat in self.threat_words:
            if threat.lower() in full_content.lower():
                red_flags.append(f'⚠️ Contains threat: "{threat}"')
                risk_score += 10

        # 6. Check spelling errors
        for error in self.common_misspellings:
            if error.lower() in full_content.lower():
                red_flags.append(f'⚠️ Spelling error: "{error}"')
                risk_score += 5

        # 7. Check attachments
        if 'attachment' in full_content.lower() or 'download' in full_content.lower():
            red_flags.append('⚠️ Mentions attachments')
            risk_score += 10

        # 8. Domain spoofing
        spoofing_result = self._check_domain_spoofing(full_content)
        if spoofing_result['is_spoofed']:
            red_flags.extend(spoofing_result['reasons'])
            risk_score += 25

        # Calculate final score
        risk_score = min(risk_score, 100)
        
        # Determine status
        if risk_score >= 70:
            status = 'phishing'
            confidence = 'High'
            is_phishing = True
        elif risk_score >= 40:
            status = 'suspicious'
            confidence = 'Medium'
            is_phishing = False
        elif risk_score >= 20:
            status = 'caution'
            confidence = 'Low'
            is_phishing = False
        else:
            status = 'safe'
            confidence = 'Low'
            is_phishing = False

        return {
            'risk_score': risk_score,
            'red_flags': red_flags,
            'status': status,
            'confidence': confidence,
            'is_phishing': is_phishing,
            'url_count': len(urls)
        }

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        pattern = r'https?://[^\s<>"]+'
        return re.findall(pattern, text)

    def _analyze_url(self, url: str) -> Dict:
        """Analyze a single URL for suspicious patterns"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'risk_score': 0
        }
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check for IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            result['reasons'].append(f'⚠️ URL uses IP address: {url}')
            result['is_suspicious'] = True
            result['risk_score'] = 30
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result['reasons'].append(f'⚠️ Suspicious TLD: {tld}')
                result['is_suspicious'] = True
                result['risk_score'] = 15
        
        return result

    def _check_domain_spoofing(self, text: str) -> Dict:
        """Check for domain spoofing attempts"""
        result = {
            'is_spoofed': False,
            'reasons': []
        }
        
        legit_domains = [
            'amazon.com', 'paypal.com', 'microsoft.com',
            'google.com', 'facebook.com', 'apple.com'
        ]
        
        for domain in legit_domains:
            base = domain.split('.')[0]
            if base in text.lower():
                if base + '0' in text.lower() or base + '-secure' in text.lower():
                    result['reasons'].append(f'⚠️ Domain spoofing: {domain}')
                    result['is_spoofed'] = True
        
        return result

    def generate_report(self, results: Dict) -> str:
        """Generate a human-readable report"""
        status_icons = {
            'phishing': '🚨',
            'suspicious': '⚠️',
            'caution': '⚡',
            'safe': '✅'
        }
        
        status_labels = {
            'phishing': 'PHISHING DETECTED',
            'suspicious': 'Suspicious',
            'caution': 'Caution',
            'safe': 'Safe'
        }
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                    PHISHING DETECTION REPORT                 ║
╠══════════════════════════════════════════════════════════════╣
║  Status: {status_icons.get(results['status'], '')} {status_labels.get(results['status'], 'Unknown')}
║  Risk Score: {results['risk_score']}/100
║  Confidence: {results['confidence'].upper()}
║  Is Phishing: {results['is_phishing']}
╠══════════════════════════════════════════════════════════════╣
║  🔍 Detected Red Flags:                                     ║
"""
        if results['red_flags']:
            for flag in results['red_flags']:
                report += f"║    • {flag}\n"
        else:
            report += "║    ✅ No red flags detected\n"
        
        report += f"""
╠══════════════════════════════════════════════════════════════╣
║  📊 Summary:                                                ║
║    URLs Found: {results['url_count']}
╚══════════════════════════════════════════════════════════════╝
"""
        return report


# ============================================
# RUN THE DETECTOR
# ============================================

if __name__ == "__main__":
    print("\n🔍 Phishing Email Detection Engine\n")
    print("=" * 50)
    
    # Test email (phishing example)
    test_email = """
    From: security@chase-bank.secure.com
    Subject: URGENT: Your account has been compromised!
    
    Dear Customer,
    
    We have detected unusual activity on your account. Please verify your identity immediately to prevent your account from being suspended.
    
    Click here to verify: https://chase-bank.secure.com/verify-account
    
    If you do not verify within 24 hours, your account will be permanently locked.
    
    Regards,
    Chase Bank Security Team
    """
    
    detector = PhishingDetector()
    result = detector.analyze_email(
        test_email,
        "security@chase-bank.secure.com",
        "URGENT: Your account has been compromised!"
    )
    
    print(detector.generate_report(result))
    
    # JSON output
    print("\n📊 JSON Output:")
    print(json.dumps(result, indent=2))