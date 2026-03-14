import re
import logging
import email
from email.policy import default
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Dict

LOGGER = logging.getLogger(__name__)

# =========================================================
# DATA CLASSES
# =========================================================

@dataclass
class Indicator:
    type: str
    value: str
    severity: str


@dataclass
class LinkFinding:
    url: str
    domain: str
    verdict: str
    risk_score: int
    reasons: List[str]


@dataclass
class AttachmentFinding:
    filename: str
    verdict: str
    risk_score: int
    reasons: List[str]


# =========================================================
# EMAIL CONTENT ANALYSIS (TEXT INDICATORS)
# =========================================================

PHISHING_KEYWORDS = [
    "verify account",
    "update account",
    "urgent",
    "suspended",
    "click here",
    "confirm password",
    "login immediately",
    "security alert",
    "bank notice",
    "unauthorized login",
]


def analyze_email_content(text: str) -> Dict[str, List[Indicator]]:
    indicators: Dict[str, List[Indicator]] = {}

    lower = text.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in lower:
            indicators.setdefault("suspicious_phrase", []).append(
                Indicator(
                    type="suspicious_phrase",
                    value=keyword,
                    severity="HIGH",
                )
            )

    # ALL CAPS words detection
    caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    for word in caps_words:
        indicators.setdefault("capitalization", []).append(
            Indicator(
                type="capitalization",
                value=word,
                severity="MEDIUM",
            )
        )

    # excessive punctuation
    punct = re.findall(r"[!?]{3,}", text)
    for p in punct:
        indicators.setdefault("excessive_punctuation", []).append(
            Indicator(
                type="excessive_punctuation",
                value=p,
                severity="LOW",
            )
        )

    return indicators


# =========================================================
# SENDER AUTHENTICATION (HEADER ANALYSIS)
# =========================================================

def analyze_email_headers(text: str) -> Dict[str, List[Indicator]]:
    indicators: Dict[str, List[Indicator]] = {}
    
    # Parse the raw email string into an EmailMessage object
    msg = email.message_from_string(text, policy=default)
    
    # Extract the Authentication-Results header, which contains SPF/DKIM/DMARC verdicts
    auth_results = msg.get_all("Authentication-Results", [])
    
    for result in auth_results:
        result_lower = result.lower()
        
        if "spf=fail" in result_lower or "spf=softfail" in result_lower:
            indicators.setdefault("Authentication", []).append(
                Indicator(
                    type="authentication_failure",
                    value="SPF verification failed",
                    severity="HIGH",
                )
            )
            
        if "dkim=fail" in result_lower:
            indicators.setdefault("Authentication", []).append(
                Indicator(
                    type="authentication_failure",
                    value="DKIM signature invalid or failed",
                    severity="HIGH",
                )
            )
            
        if "dmarc=fail" in result_lower:
            indicators.setdefault("Authentication", []).append(
                Indicator(
                    type="authentication_failure",
                    value="DMARC policy failed",
                    severity="CRITICAL",
                )
            )
            
    return indicators


# =========================================================
# LINK DETECTION
# =========================================================

URL_REGEX = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE,
)

SUSPICIOUS_DOMAINS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "confirm",
    "signin",
]


def extract_and_assess_links(text: str) -> List[LinkFinding]:
    findings: List[LinkFinding] = []

    matches = URL_REGEX.findall(text)

    for raw_url in matches:
        url = raw_url.strip("()[]<>.,;\"' ")

        if not url.startswith("http"):
            url = "http://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        risk = 0
        reasons = []

        if any(word in domain for word in SUSPICIOUS_DOMAINS):
            risk += 40
            reasons.append("Suspicious keyword in domain")

        if "-" in domain:
            risk += 10
            reasons.append("Hyphen in domain")

        if re.search(r"\d{2,}", domain):
            risk += 10
            reasons.append("Numbers in domain")

        # Homograph / Punycode Attack Detection
        if domain.startswith("xn--") or not domain.isascii():
            risk += 40
            reasons.append("Potential Homograph Attack (Punycode / Non-ASCII domain)")

        if len(domain) > 30:
            risk += 15
            reasons.append("Very long domain")

        verdict = "SAFE"
        if risk >= 60:
            verdict = "PHISHING"
        elif risk >= 25:
            verdict = "SUSPICIOUS"

        findings.append(
            LinkFinding(
                url=url,
                domain=domain,
                verdict=verdict,
                risk_score=risk,
                reasons=reasons or ["No suspicious signals"],
            )
        )

    return findings


# =========================================================
# ATTACHMENT DETECTION
# =========================================================

ATTACHMENT_REGEX = re.compile(
    r"(?:^|[\s\-•*>])([\w\-. ]+\.(exe|zip|rar|pdf|docx?|xls[xm]?|pptx?|js|bat|scr))",
    re.IGNORECASE,
)

DANGEROUS_EXTENSIONS = ["exe", "scr", "bat", "js"]


def extract_and_assess_attachments(text: str) -> List[AttachmentFinding]:
    findings: List[AttachmentFinding] = []

    matches = ATTACHMENT_REGEX.findall(text)

    for match in matches:
        filename = match[0].strip()
        ext = filename.split(".")[-1].lower()

        risk = 0
        reasons = []

        if ext in DANGEROUS_EXTENSIONS:
            risk += 70
            reasons.append("Executable attachment")

        if "verify" in filename.lower() or "account" in filename.lower():
            risk += 25
            reasons.append("Sensitive filename keyword")

        if len(filename) > 25:
            risk += 10
            reasons.append("Long filename")

        verdict = "SAFE"
        if risk >= 60:
            verdict = "PHISHING"
        elif risk >= 25:
            verdict = "SUSPICIOUS"

        findings.append(
            AttachmentFinding(
                filename=filename,
                verdict=verdict,
                risk_score=risk,
                reasons=reasons or ["No suspicious signals"],
            )
        )

    return findings
