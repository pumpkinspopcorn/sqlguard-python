"""Module 3: Warning Logic - Filters and reports vulnerabilities"""

import json
from typing import List
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unified_types import VulnerabilityEvent


class WarningDecisionLogic:
    """Filters and reports vulnerabilities"""
    
    def __init__(self, symbol_table=None):
        self.symbol_table = symbol_table
        self.warnings: List[VulnerabilityEvent] = []
        self.filtered_events: List[VulnerabilityEvent] = []
        self.statistics = {
            'total_events': 0,
            'warnings_issued': 0,
            'filtered_out': 0,
            'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
    
    def process_vulnerability(self, vulnerability: VulnerabilityEvent) -> bool:
        """Process a vulnerability event"""
        self.statistics['total_events'] += 1
        
        if self._should_filter(vulnerability):
            self.filtered_events.append(vulnerability)
            self.statistics['filtered_out'] += 1
            return False
        
        self.warnings.append(vulnerability)
        self.statistics['warnings_issued'] += 1
        self.statistics['by_severity'][vulnerability.severity] += 1
        return True
    
    def _should_filter(self, vulnerability: VulnerabilityEvent) -> bool:
        """Apply false positive filtering"""
        if vulnerability.confidence < 0.6:
            return True
        if self.symbol_table:
            from unified_types import TaintState
            var_taint = self.symbol_table.get_taint(vulnerability.variable_name)
            if var_taint == TaintState.SANITIZED:
                return True
        return False
    
    def _get_suggested_fix(self, construction: str) -> str:
        """Get suggested fix based on construction type"""
        fixes = {
            # SQL fixes (original)
            'string_concatenation': "Use parameterized queries with placeholders (?, :param) instead of string concatenation",
            'format_string':        "Use parameterized queries instead of format strings",
            'direct_variable':      "Sanitize input or use parameterized queries",
            # ORM fixes (new)
            'orm_raw_concat':    "Avoid building raw SQL strings with concatenation; use Django's parameterized .raw('SELECT ... WHERE id = %s', [user_input]) instead",
            'orm_raw_direct':    "Avoid passing tainted variables directly to .raw(); use parameterized .raw() with a params list/dict",
            'orm_text_wrapper':  "Use SQLAlchemy text() with bindparams: text('SELECT ... WHERE id = :id').bindparams(id=user_input)",
            'orm_filter':        "Use Django ORM's safe filter syntax (e.g., .filter(username=var)); avoid __regex or __contains with raw user input",
            'orm_where':         "Use ORM parameterized where clauses instead of passing raw tainted strings to .where()",
        }
        return fixes.get(construction, "Use parameterized queries or ORM safe APIs to prevent injection")
    
    def _get_rule_violated(self, construction: str) -> str:
        """Get rule violated description"""
        rules = {
            # SQL rules (original)
            'string_concatenation': "SQL-CONCAT: Tainted data in string concatenation",
            'format_string':        "SQL-FORMAT: Tainted data in format string",
            'direct_variable':      "SQL-DIRECT: Tainted data directly used in query",
            # ORM rules (new)
            'orm_raw_concat':    "ORM-RAW-CONCAT: Tainted data in ORM .raw() via string concatenation",
            'orm_raw_direct':    "ORM-RAW-DIRECT: Tainted variable passed directly to ORM .raw()",
            'orm_text_wrapper':  "ORM-TEXT: Tainted data inside SQLAlchemy text() wrapper",
            'orm_filter':        "ORM-FILTER: Tainted data in ORM .filter()/.get() lookup",
            'orm_where':         "ORM-WHERE: Tainted data in ORM .where() clause",
        }
        return rules.get(construction, "INJECTION: Tainted data flows into query sink")
    
    def generate_text_report(self) -> str:
        """Generate human-readable report"""
        report = [
            "=" * 70,
            "SQL / ORM INJECTION VULNERABILITY REPORT",
            "=" * 70,
            f"\nTotal Vulnerabilities Found: {len(self.warnings)}",
            f"High Severity: {self.statistics['by_severity']['HIGH']}",
            f"Medium Severity: {self.statistics['by_severity']['MEDIUM']}",
            f"Events Filtered: {self.statistics['filtered_out']}",
            "\n" + "=" * 70
        ]
        
        for idx, vuln in enumerate(self.warnings, 1):
            rule_violated = self._get_rule_violated(vuln.query_construction)
            suggested_fix = self._get_suggested_fix(vuln.query_construction)
            
            report.extend([
                f"\n[{idx}] {vuln.vulnerability_id} - {vuln.severity} SEVERITY",
                f"    Line: {vuln.line_number}",
                f"    Function: {vuln.function_name}",
                f"    Variable: {vuln.variable_name}",
                f"    Sink: {vuln.sink_type}",
                f"    Rule Violated: {rule_violated}",
                f"    Construction: {vuln.query_construction}",
                f"    Description: {vuln.description}",
                f"    Suggested Fix: {suggested_fix}",
                ""
            ])
        
        report.append("=" * 70)
        return "\n".join(report)
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report_data = {
            'summary': {
                'total_vulnerabilities': len(self.warnings),
                'high_severity': self.statistics['by_severity']['HIGH'],
                'medium_severity': self.statistics['by_severity']['MEDIUM'],
                'filtered': self.statistics['filtered_out']
            },
            'vulnerabilities': [
                {
                    'id': v.vulnerability_id,
                    'severity': v.severity,
                    'line': v.line_number,
                    'variable': v.variable_name,
                    'sink': v.sink_type,
                    'rule_violated': self._get_rule_violated(v.query_construction),
                    'construction': v.query_construction,
                    'description': v.description,
                    'suggested_fix': self._get_suggested_fix(v.query_construction)
                }
                for v in self.warnings
            ]
        }
        return json.dumps(report_data, indent=2)
    
    def print_summary(self):
        """Print concise summary"""
        print("\n")
        print("VULNERABILITY DETECTION SUMMARY")
        print("\n")
        print(f"Total Events Processed: {self.statistics['total_events']}")
        print(f"Warnings Issued: {self.statistics['warnings_issued']}")
        print(f"  - HIGH severity: {self.statistics['by_severity']['HIGH']}")
        print(f"  - MEDIUM severity: {self.statistics['by_severity']['MEDIUM']}")
        print(f"Filtered Out: {self.statistics['filtered_out']}")
        print("\n")
