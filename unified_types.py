"""Unified Type Definitions - Integration Layer for Component 1 and Component 2

This module provides a unified interface for both components to interact with
shared data structures, particularly the symbol table and taint states.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


# TAINT TRACKING

      
class TaintState(Enum):
    
    """Taint classification for variables"""
    TAINTED = "TAINTED"
    UNTAINTED = "UNTAINTED"
    UNKNOWN = "UNKNOWN"
    SANITIZED = "SANITIZED"  # Added for Component 1 compatibility

#query = "SELECT * FROM users WHERE id = " + user_input
#above is the example for tainted as right side is tainted then left side is also tainted
def combine_taint(left: TaintState, right: TaintState)-> TaintState:
    """ THis combines the taint stats for the binary expressions.
            if either side is tainted then the result is also tainted
            it is only sanitized is both sides are sanitized
            Unknown propagates conservatively    """
    if left == TaintState.TAINTED or right == TaintState.TAINTED:
        return TaintState.TAINTED
    if left == TaintState.UNKNOWN or right == TaintState.UNKNOWN:
        return TaintState.UNKNOWN
    if left == TaintState.SANITIZED and right == TaintState.SANITIZED:
        return TaintState.SANITIZED
    return TaintState.UNTAINTED



def evaluate_expression_taint(expr, symbol_table)-> TaintState:
    """  This function defines the taint proagation semantics
    the front-end modules( input detection and rule engine) must call this instead of implementing their own expression analysis
    no propagation logic should exist outside this file"""

    if expr is None:
        return TaintState.UNKNOWN
    # Identifier: inherit taint from the sumbol table
    if expr.type== 'Identifier':
        return symbol_table.get_taint(expr.name)
    
    # Literals are always untainted
    if expr.type in ('StringLiteral','NumberLiteral'):
        return TaintState.UNTAINTED
    
    # Binary expression: combine the taints
    if expr.type == 'BinaryExpression':
        left = evaluate_expression_taint(expr.left,symbol_table)
        right = evaluate_expression_taint(expr.right,symbol_table)
        return combine_taint(left,right)
    #if any argument in the function is tianted then the return is tainted
    if expr.type== 'FunctionCall':
        for arg in expr.arguments:
            if evaluate_expression_taint(arg,symbol_table)==TaintState.TAINTED:
                return TaintState.TAINTED
            
        return TaintState.UNKNOWN
    return TaintState.UNKNOWN
def compute_taint_flow(expr, symbol_table) -> List[str]:
    """ Compute a simple taint flow path for reporting"""
    flow=[]

    if expr is None:
        return flow
    #if the identifier is tainted then add it to the taint flow
    if expr.type=='Identifier':
        if symbol_table.get_taint(expr.name) == TaintState.TAINTED:
            flow.append(expr.name)
        return flow
    #similarly for binary and functioncall below also
    if expr.type== 'BinaryExpression':
        flow.extend(compute_taint_flow(expr.left,symbol_table))
        flow.extend(compute_taint_flow(expr.right, symbol_table))
        return flow
    
    if expr.type== 'FunctionCall':
        for arg in expr.arguments:
            flow.extend(compute_taint_flow(arg,symbol_table))
        return flow
    return flow
class SymbolTable:
    """Unified symbol table maintaining variable taint states across scopes
    
    This implementation is based on Component 2's symbol table with enhanced
    features for scope management. It provides both the new interface
    (set_taint/get_taint) and legacy interface (set/get) for compatibility.
    Component 1 and 2 are previous implentations(structurally) so wrapper functions were made for integrations between component 1 and component 2
    """
    #The scope is used to differentiate between variables to recognise them efficiently
    # If two variables have the same name but are different based on their scopes this progam correctly differentitates between two and checks both of them
     
    def __init__(self):
        self.scopes: List[Dict[str, TaintState]] = [{}]  # Start with global scope
    # each dictionary is one scope
    #each list is for new scope
    def enter_scope(self):
        """Enter a new scope (e.g., function, block)"""
        self.scopes.append({})
    #removes last scope(the current scope)
    def exit_scope(self):
        """Exit current scope, returning to parent scope"""
        if len(self.scopes) > 1:
            self.scopes.pop()
    
    def set_taint(self, var_name: str, taint_state: TaintState):
        """Set taint state for a variable in current scope(Always overwrites previous taint)
        also no taint history is preserved"""
        # Handle both TaintState enum and string values for compatibility
        if isinstance(taint_state, str):
            taint_state = TaintState(taint_state)
        self.scopes[-1][var_name] = taint_state
    
    def get_taint(self, var_name: str) -> TaintState:
        """Get taint state for a variable, searching from innermost to outermost scope"""
        for scope in reversed(self.scopes):
            if var_name in scope:
                return scope[var_name]
        return TaintState.UNKNOWN
    
    # Legacy interface for Component 1 compatibility
    def set(self, variable: str, taint):
        """ interface: set taint state (Component 1 compatibility)"""
        previous = self.get(variable)
        self.set_taint(variable, taint)
        return previous
    
    def get(self, variable: str):
        """ interface: get taint state (Component 1 compatibility)"""
        taint_state = self.get_taint(variable)
        # Return string value for Component 1 compatibility
        return taint_state.value if isinstance(taint_state, TaintState) else taint_state
    
    def get_all_variables(self) -> Dict[str, TaintState]:
        """Get all variables and their taint states across all scopes"""
        all_vars = {}
        for scope in self.scopes:
            all_vars.update(scope)
        return all_vars
    
    def __repr__(self):
        return f"SymbolTable(scopes={len(self.scopes)}, vars={self.get_all_variables()})"


# VULNERABILITY EVENTS

@dataclass
class VulnerabilityEvent:
    """Represents a detected vulnerability"""
    vulnerability_id: str
    line_number: int
    file_path: Optional[str]
    function_name: str
    variable_name: str
    sink_type: str
    query_construction: str
    severity: str
    description: str
    taint_flow: List[str] = field(default_factory=list)
    confidence: float = 1.0



# AST NODE CLASSES

class ASTNode:
    """Base class for AST nodes"""
    def __init__(self, node_type: str, line_number: int = -1, file_path: str = None):
        self.type = node_type
        self.line_number = line_number
        self.file_path = file_path
        self.children = []


class IdentifierNode(ASTNode):
    """Identifier node (variable name)"""
    def __init__(self, name: str, line_number: int = -1):
        super().__init__('Identifier', line_number)
        self.name = name


class StringLiteralNode(ASTNode):
    """String literal node"""
    def __init__(self, value: str, line_number: int = -1):
        super().__init__('StringLiteral', line_number)
        self.value = value


class NumberLiteralNode(ASTNode):
    """Number literal node"""
    def __init__(self, value: float, line_number: int = -1):
        super().__init__('NumberLiteral', line_number)
        self.value = value


class BinaryExpressionNode(ASTNode):
    """Binary expression (e.g., a + b)"""
    def __init__(self, left, operator: str, right, line_number: int = -1):
        super().__init__('BinaryExpression', line_number)
        self.left = left
        self.operator = operator
        self.right = right


class FunctionCallNode(ASTNode):
    """Function call node"""
    def __init__(self, function, arguments: List, line_number: int = -1):
        super().__init__('FunctionCall', line_number)
        self.function = function
        self.arguments = arguments


class MemberAccessNode(ASTNode):
    """Member access (e.g., object.method)"""
    def __init__(self, obj, property_name: str, line_number: int = -1):
        super().__init__('MemberAccess', line_number)
        self.object = obj
        self.property = IdentifierNode(property_name)


class AssignmentNode(ASTNode):
    """Assignment statement"""
    def __init__(self, variable: str, expression, line_number: int = -1):
        super().__init__('AssignmentStatement', line_number)
        self.variable = variable
        self.expression = expression


class ProgramNode(ASTNode):
    """Root program node"""
    def __init__(self, statements: List):
        super().__init__('Program')
        self.children = statements


# Aliases for Component 1 compatibility
# If component 1 has VariableNode it will be converted to IdentifierNode
VariableNode = IdentifierNode
