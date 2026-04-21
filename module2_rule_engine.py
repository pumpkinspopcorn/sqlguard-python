"""Module 2: Rule Engine - Detects SQL injection and ORM injection vulnerabilities"""

from typing import Optional, Dict
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unified_types import SymbolTable, TaintState, ASTNode, FunctionCallNode, VulnerabilityEvent


class RuleEngineModule:
    """Applies vulnerability detection rules"""
    
    SQL_SINKS = {'execute', 'executeQuery', 'executeUpdate', 'query', 'exec'}

    # ORM sinks: methods used by SQLAlchemy, Django ORM, Peewee, etc.
    # 'raw'      -> Django ORM  User.objects.raw("SELECT ..." + user_input)
    # 'filter'   -> Django ORM  User.objects.filter(username__regex=user_input)
    # 'where'    -> Peewee/SQLAlchemy Core  .where(SQL(user_input))
    # 'get'      -> Django ORM  User.objects.get(user_input)
    # 'text'     -> SQLAlchemy  text("SELECT ..." + user_input)
    # 'select'   -> SQLAlchemy/Peewee .select() with raw tainted string
    # 'having'   -> ORM .having() with tainted expression
    # 'order_by' -> ORM .order_by() with tainted column name
    ORM_SINKS = {'filter', 'raw', 'where', 'get', 'text', 'select', 'having', 'order_by'}

    def __init__(self, symbol_table: SymbolTable):
        self.symbol_table = symbol_table
        self.detected_vulnerabilities = []
        self.vuln_counter = 0
        self.orm_vuln_counter = 0

    # ------------------------------------------------------------------
    # SQL DETECTION  (original — completely unchanged)
    # ------------------------------------------------------------------

    def apply_detection_rules(self, node: FunctionCallNode) -> Optional[VulnerabilityEvent]:
        """Apply core SQL vulnerability detection rule"""
        if not self._is_sql_sink(node):
            return None
        
        if not hasattr(node, 'arguments') or len(node.arguments) == 0:
            return None
        
        query_arg = node.arguments[0]
        
        if len(node.arguments) >= 2 and self._has_placeholders(query_arg):
            return None
        
        is_vulnerable, taint_info = self._check_vulnerability_condition(query_arg)
        if not is_vulnerable:
            return None
        
        construction = self._analyze_construction(query_arg)
        rule_explanation = self._get_rule_explanation(construction)
        severity = 'HIGH' if construction == 'string_concatenation' else 'MEDIUM'
        
        self.vuln_counter += 1
        vulnerability = VulnerabilityEvent(
            vulnerability_id=f"SQLI-{self.vuln_counter:04d}",
            line_number=node.line_number,
            file_path=node.file_path,
            function_name=self._get_function_name(node),
            variable_name=taint_info.get('variable', 'unknown'),
            sink_type=self._get_sink_type(node),
            query_construction=construction,
            severity=severity,
            description=f"{rule_explanation}. Variable '{taint_info.get('variable', 'unknown')}' "
                       f"is tainted and flows to SQL sink '{self._get_sink_type(node)}'. "
                       f"Use parameterized queries to prevent SQL injection.",
            confidence=0.95
        )
        
        self.detected_vulnerabilities.append(vulnerability)
        return vulnerability

    # ------------------------------------------------------------------
    # ORM DETECTION  (new — built on top of existing shared helpers)
    # ------------------------------------------------------------------

    def apply_orm_detection_rules(self, node: FunctionCallNode) -> Optional[VulnerabilityEvent]:
        """Detect ORM injection: tainted data flowing into an ORM sink.

        Reuses _check_vulnerability_condition, _get_sink_type, and
        _get_function_name — no duplication with the SQL path.
        """
        if not self._is_orm_sink(node):
            return None

        if not hasattr(node, 'arguments') or len(node.arguments) == 0:
            return None

        # Check every argument — ORM methods like filter() can take
        # multiple args, any of which may carry tainted data.
        taint_info: Dict = {}
        vulnerable_arg = None
        for arg in node.arguments:
            is_vuln, info = self._check_vulnerability_condition(arg)
            if is_vuln:
                taint_info.update(info)
                vulnerable_arg = arg
                break

        if vulnerable_arg is None:
            return None

        construction = self._analyze_orm_construction(node, vulnerable_arg)
        rule_explanation = self._get_orm_rule_explanation(construction)

        # .raw() and text() with tainted strings are HIGH risk;
        # .filter() / .where() / .get() with tainted args are MEDIUM.
        sink_method = node.function.property.name
        severity = 'HIGH' if sink_method in ('raw', 'text') else 'MEDIUM'

        self.orm_vuln_counter += 1
        vulnerability = VulnerabilityEvent(
            vulnerability_id=f"ORMI-{self.orm_vuln_counter:04d}",
            line_number=node.line_number,
            file_path=node.file_path,
            function_name=self._get_function_name(node),
            variable_name=taint_info.get('variable', 'unknown'),
            sink_type=self._get_sink_type(node),
            query_construction=construction,
            severity=severity,
            description=(
                f"{rule_explanation}. "
                f"Variable '{taint_info.get('variable', 'unknown')}' is tainted "
                f"and flows into ORM sink '{self._get_sink_type(node)}'. "
                f"Use parameterized ORM queries to prevent injection."
            ),
            confidence=0.90
        )

        self.detected_vulnerabilities.append(vulnerability)
        return vulnerability

    def _analyze_orm_construction(self, sink_node: FunctionCallNode, arg) -> str:
        """Classify how tainted data reaches the ORM sink."""
        sink_method = sink_node.function.property.name

        if sink_method == 'raw':
            if arg.type == 'BinaryExpression' and arg.operator == '+':
                return 'orm_raw_concat'
            return 'orm_raw_direct'

        if sink_method == 'text':
            return 'orm_text_wrapper'

        if sink_method in ('filter', 'get', 'having', 'order_by'):
            return 'orm_filter'

        if sink_method == 'where':
            return 'orm_where'

        # Fallback: reuse existing SQL construction analysis on the arg
        return self._analyze_construction(arg)

    def _get_orm_rule_explanation(self, construction: str) -> str:
        """Rule explanations for ORM-specific construction types."""
        explanations = {
            'orm_raw_concat':   "Tainted data flows into ORM .raw() via string concatenation",
            'orm_raw_direct':   "Tainted variable flows directly into ORM .raw() query",
            'orm_text_wrapper': "Tainted data flows into SQLAlchemy text() wrapper",
            'orm_filter':       "Tainted data flows into ORM .filter()/.get() — risk of regex or lookup injection",
            'orm_where':        "Tainted data flows into ORM .where() clause",
            # Shared fallbacks
            'string_concatenation': "Tainted data flows into ORM sink via string concatenation",
            'format_string':        "Tainted data flows into ORM sink via format string",
            'direct_variable':      "Tainted data flows directly into ORM sink",
        }
        return explanations.get(construction, "Tainted data flows into ORM sink")

    # ------------------------------------------------------------------
    # SINK CHECKERS
    # ------------------------------------------------------------------

    def _is_sql_sink(self, node: FunctionCallNode) -> bool:
        """Check if this is a raw SQL sink"""
        if node.function.type == 'Identifier':
            return node.function.name in self.SQL_SINKS
        if node.function.type == 'MemberAccess':
            return node.function.property.name in self.SQL_SINKS
        return False

    def _is_orm_sink(self, node: FunctionCallNode) -> bool:
        """Check if this is an ORM sink.

        Requires MemberAccess (obj.method) so that bare calls like
        filter(...) at module level do NOT trigger false positives.
        ORM calls always appear as queryset.filter(...), objects.raw(...), etc.
        """
        if node.function.type == 'MemberAccess':
            return node.function.property.name in self.ORM_SINKS
        return False

    # ------------------------------------------------------------------
    # SHARED HELPERS  (used by both SQL and ORM paths — unchanged)
    # ------------------------------------------------------------------

    def _has_placeholders(self, node: ASTNode) -> bool:
        """Check for SQL parameter placeholders"""
        if node.type == 'StringLiteral':
            return any(ph in node.value for ph in ['?', ':param', '%s', '$1'])
        return False
    
    def _check_vulnerability_condition(self, query_node: ASTNode) -> tuple:
        """Check if query contains tainted data"""
        taint_info = {}
        
        if query_node.type == 'Identifier':
            var_name = query_node.name
            taint_state = self.symbol_table.get_taint(var_name)
            if taint_state == TaintState.TAINTED:
                taint_info['variable'] = var_name
                return True, taint_info
        
        elif query_node.type == 'BinaryExpression':
            left_vuln, left_info = self._check_vulnerability_condition(query_node.left)
            right_vuln, right_info = self._check_vulnerability_condition(query_node.right)
            if left_vuln or right_vuln:
                taint_info.update(left_info)
                taint_info.update(right_info)
                return True, taint_info
        
        return False, {}
    
    def _analyze_construction(self, query_node: ASTNode) -> str:
        """Analyze how query is constructed (SQL path; also used as ORM fallback)"""
        if query_node.type == 'BinaryExpression':
            if query_node.operator == '+':
                return 'string_concatenation'
            elif query_node.operator == '%':
                return 'format_string'
        if query_node.type == 'FunctionCall':
            if query_node.function.type == 'MemberAccess':
                if query_node.function.property.name == 'format':
                    return 'format_string'
        return 'direct_variable'
    
    def _get_rule_explanation(self, construction: str) -> str:
        """Get rule explanation for SQL construction types"""
        explanations = {
            'string_concatenation': "Tainted data flows into SQL sink via string concatenation",
            'format_string':        "Tainted data flows into SQL sink via format string",
            'direct_variable':      "Tainted data flows directly into SQL sink",
        }
        return explanations.get(construction, "Tainted data flows into SQL sink")
    
    def _get_function_name(self, node: FunctionCallNode) -> str:
        """Extract function name"""
        if node.function.type == 'Identifier':
            return node.function.name
        return node.function.property.name
    
    def _get_sink_type(self, node: FunctionCallNode) -> str:
        """Extract sink type"""
        if node.function.type == 'MemberAccess':
            obj_name = getattr(node.function.object, 'name', 'object')
            method_name = node.function.property.name
            return f"{obj_name}.{method_name}"
        return self._get_function_name(node)
