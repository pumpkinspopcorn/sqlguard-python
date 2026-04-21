"""
AI-Powered Self-Healing Module
Generates fixed code versions for detected vulnerabilities
"""

import re
from typing import Dict, List, Tuple


class AICodeHealer:
    """Generates secure code fixes for SQL injection vulnerabilities"""
    
    def __init__(self):
        self.fix_patterns = self._initialize_fix_patterns()
    
    def _initialize_fix_patterns(self) -> Dict:
        """Initialize fix patterns for different vulnerability types"""
        return {
            'string_concatenation': self._fix_string_concatenation,
            'format_string': self._fix_format_string,
            'direct_variable': self._fix_direct_variable,
            'orm_raw_concat': self._fix_orm_raw_concat,
            'orm_raw_direct': self._fix_orm_raw_direct,
            'orm_text_wrapper': self._fix_orm_text_wrapper,
            'orm_filter': self._fix_orm_filter,
            'orm_where': self._fix_orm_where,
        }
    
    def generate_fix(self, vulnerability: Dict, source_code: str) -> Dict:
        """Generate a fixed version of vulnerable code"""
        construction = vulnerability.get('construction', '')
        line_number = vulnerability.get('line', 0)
        
        # Extract vulnerable line
        lines = source_code.split('\n')
        if line_number < 1 or line_number > len(lines):
            return {
                'success': False,
                'error': 'Invalid line number'
            }
        
        vulnerable_line = lines[line_number - 1]
        
        # Apply appropriate fix
        fix_func = self.fix_patterns.get(construction)
        if not fix_func:
            return {
                'success': False,
                'error': f'No fix pattern for construction type: {construction}'
            }
        
        fixed_line, explanation = fix_func(vulnerable_line, vulnerability)
        
        # Generate full fixed code
        fixed_lines = lines.copy()
        fixed_lines[line_number - 1] = fixed_line
        
        return {
            'success': True,
            'original_line': vulnerable_line.strip(),
            'fixed_line': fixed_line.strip(),
            'full_fixed_code': '\n'.join(fixed_lines),
            'explanation': explanation,
            'line_number': line_number
        }
    
    def _fix_string_concatenation(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix SQL string concatenation vulnerability"""
        indent = len(line) - len(line.lstrip())
        
        # Detect cursor.execute pattern
        if 'execute' in line.lower():
            # Extract variable names from concatenation
            var_match = re.search(r'(\w+)\s*\+\s*["\']', line)
            if var_match:
                var_name = var_match.group(1)
                
                # Check if it's a simple SELECT/INSERT/UPDATE
                if 'SELECT' in line.upper():
                    fixed = ' ' * indent + f'cursor.execute("SELECT * FROM users WHERE username = ?", ({var_name},))'
                    explanation = f"Replaced string concatenation with parameterized query using '?' placeholder and tuple parameter"
                elif 'INSERT' in line.upper():
                    fixed = ' ' * indent + f'cursor.execute("INSERT INTO users (username) VALUES (?)", ({var_name},))'
                    explanation = "Replaced string concatenation with parameterized INSERT using '?' placeholder"
                else:
                    fixed = ' ' * indent + f'cursor.execute(query, ({var_name},))  # Use parameterized query'
                    explanation = "Replaced string concatenation with parameterized query pattern"
                
                return fixed, explanation
        
        # Generic fix
        fixed = line.replace('+', ',')
        return fixed, "Converted concatenation to parameterized query (manual adjustment may be needed)"
    
    def _fix_format_string(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix format string vulnerability"""
        indent = len(line) - len(line.lstrip())
        
        if '.format(' in line:
            # Extract variable from format
            var_match = re.search(r'\.format\((\w+)\)', line)
            if var_match:
                var_name = var_match.group(1)
                # Replace .format() with parameterized query
                fixed = re.sub(r'\{[^}]*\}', '?', line)
                fixed = re.sub(r'\.format\([^)]+\)', f', ({var_name},)', fixed)
                return fixed, f"Replaced .format() with parameterized query using '?' placeholder"
        
        if '%' in line and 'execute' in line.lower():
            # Old-style % formatting
            var_match = re.search(r'%\s*(\w+)', line)
            if var_match:
                var_name = var_match.group(1)
                fixed = re.sub(r'%s', '?', line)
                fixed = re.sub(r'%\s*\w+', f', ({var_name},)', fixed)
                return fixed, "Replaced % formatting with parameterized query"
        
        return line, "Manual review needed for format string fix"
    
    def _fix_direct_variable(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix direct variable usage in SQL"""
        indent = len(line) - len(line.lstrip())
        var_name = vuln.get('variable', 'user_input')
        
        if 'execute' in line.lower():
            # Add parameterization
            if '(' in line and ')' in line:
                # Find the query argument
                match = re.search(r'execute\s*\(\s*(\w+)', line, re.IGNORECASE)
                if match:
                    query_var = match.group(1)
                    fixed = re.sub(
                        r'execute\s*\(\s*\w+\s*\)',
                        f'execute({query_var}, ({var_name},))',
                        line,
                        flags=re.IGNORECASE
                    )
                    return fixed, f"Added parameterization: passing {var_name} as a tuple parameter"
        
        return line + f'  # TODO: Use parameterized query with {var_name}', "Added TODO comment for manual fix"
    
    def _fix_orm_raw_concat(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix ORM .raw() with concatenation"""
        indent = len(line) - len(line.lstrip())
        
        # Extract variable from concatenation
        var_match = re.search(r'(\w+)\s*\+', line)
        if var_match:
            var_name = var_match.group(1)
            
            # Replace concatenation with parameterized .raw()
            fixed = re.sub(r'["\'][^"\']*["\']\s*\+\s*\w+', '"%s"', line)
            fixed = re.sub(r'\.raw\([^)]+\)', f'.raw("SELECT * FROM table WHERE id = %s", [{var_name}])', fixed)
            
            return fixed, f"Replaced concatenation with Django's parameterized .raw() using %s placeholder and list parameter"
        
        return line, "Manual review needed for ORM raw concatenation fix"
    
    def _fix_orm_raw_direct(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix ORM .raw() with direct variable"""
        var_name = vuln.get('variable', 'user_input')
        
        if '.raw(' in line:
            # Add parameterization
            fixed = re.sub(
                r'\.raw\((\w+)\)',
                f'.raw("SELECT * FROM table WHERE id = %s", [{var_name}])',
                line
            )
            return fixed, f"Added parameterization to .raw() method with {var_name} as list parameter"
        
        return line, "Manual review needed for ORM raw direct fix"
    
    def _fix_orm_text_wrapper(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix SQLAlchemy text() wrapper"""
        var_name = vuln.get('variable', 'user_input')
        
        if 'text(' in line:
            # Add bindparams
            fixed = re.sub(
                r'text\([^)]+\)',
                f'text("SELECT * FROM table WHERE id = :id").bindparams(id={var_name})',
                line
            )
            return fixed, f"Added .bindparams() to SQLAlchemy text() with named parameter :id"
        
        return line, "Manual review needed for text() wrapper fix"
    
    def _fix_orm_filter(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix ORM .filter() with tainted data"""
        var_name = vuln.get('variable', 'user_input')
        
        if '.filter(' in line:
            # Replace with safe filter syntax
            fixed = re.sub(
                r'\.filter\([^)]+\)',
                f'.filter(username={var_name})',
                line
            )
            return fixed, f"Replaced with Django ORM's safe filter syntax using keyword argument"
        
        return line, "Manual review needed for ORM filter fix"
    
    def _fix_orm_where(self, line: str, vuln: Dict) -> Tuple[str, str]:
        """Fix ORM .where() clause"""
        var_name = vuln.get('variable', 'user_input')
        
        if '.where(' in line:
            # Use parameterized where
            fixed = re.sub(
                r'\.where\([^)]+\)',
                f'.where(table.c.id == bindparam("id", {var_name}))',
                line
            )
            return fixed, f"Replaced with parameterized .where() using bindparam()"
        
        return line, "Manual review needed for ORM where fix"
    
    def generate_batch_fixes(self, vulnerabilities: List[Dict], source_code: str) -> Dict:
        """Generate fixes for all vulnerabilities in a file"""
        fixes = []
        fixed_code = source_code
        
        # Sort vulnerabilities by line number (descending) to avoid line number shifts
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get('line', 0), reverse=True)
        
        for vuln in sorted_vulns:
            fix_result = self.generate_fix(vuln, fixed_code)
            if fix_result['success']:
                fixes.append({
                    'vulnerability_id': vuln.get('id'),
                    'line': vuln.get('line'),
                    'original': fix_result['original_line'],
                    'fixed': fix_result['fixed_line'],
                    'explanation': fix_result['explanation']
                })
                fixed_code = fix_result['full_fixed_code']
        
        return {
            'success': True,
            'fixes': fixes,
            'fixed_code': fixed_code,
            'total_fixes': len(fixes)
        }
