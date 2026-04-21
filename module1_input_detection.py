
from typing import List
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unified_types import evaluate_expression_taint,SymbolTable, TaintState, ASTNode, AssignmentNode


class InputDetectionModule:
    """Detects taint sources and updates symbol table"""
    
    TAINT_SOURCES = {
        'input', 'raw_input', 'readLine', 'nextLine',
        'getParameter', 'getQueryString', 'getHeader', 'getCookie',
        'request.getParameter', 'Scanner.nextLine'
    }
    
    SANITIZATION_FUNCTIONS = {
        # Existing SQL sanitizers
        'sanitize', 'escapeSql', 'prepareStatement',
        # ORM / SQLAlchemy safe parameterization functions.
        # When user input is passed through these it is marked SANITIZED
        # and will NOT trigger an ORM injection warning.
        'bindparam', 'literal', 'func',
    }
    
    def __init__(self, symbol_table: SymbolTable):
        self.symbol_table = symbol_table
        self.detected_sources = []
        self.detected_sanitizations = []
    
    def detect_taint_source(self, assignment_node: AssignmentNode) -> bool:
        """Check if assignment introduces tainted data"""
        var_name = assignment_node.variable
        expr = assignment_node.expression
        
        if self._is_sanitization_function(expr):
            self.symbol_table.set_taint(var_name, TaintState.SANITIZED)
            self.detected_sanitizations.append({
                'variable': var_name,
                'line': assignment_node.line_number,
                'sanitizer': self._get_source_name(expr)
            })
            return False
        
        if self._is_taint_source(expr):
            self.symbol_table.set_taint(var_name, TaintState.TAINTED)
            self.detected_sources.append({
                'variable': var_name,
                'line': assignment_node.line_number,
                'source': self._get_source_name(expr)
            })
            return True
        
        taint_state = evaluate_expression_taint(expr, self.symbol_table)
        self.symbol_table.set_taint(var_name, taint_state)
        return taint_state == TaintState.TAINTED
    
    def _is_taint_source(self, expr_node: ASTNode) -> bool:
        if expr_node.type != 'FunctionCall':
            return False
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name in self.TAINT_SOURCES
        if expr_node.function.type == 'MemberAccess':
            return expr_node.function.property.name in self.TAINT_SOURCES
        return False
    
    def _is_sanitization_function(self, expr_node: ASTNode) -> bool:
        if expr_node.type != 'FunctionCall':
            return False
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name in self.SANITIZATION_FUNCTIONS
        if expr_node.function.type == 'MemberAccess':
            return expr_node.function.property.name in self.SANITIZATION_FUNCTIONS
        return False
    
    def _get_source_name(self, expr_node: ASTNode) -> str:
        if expr_node.function.type == 'Identifier':
            return expr_node.function.name
        return expr_node.function.property.name
