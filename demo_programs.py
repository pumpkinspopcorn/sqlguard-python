# demo_programs.py
"""
Contains all demonstration programs for Week 6 system.
"""

from unified_types import *



def vulnerable_concat_program():
    input_call = FunctionCallNode(IdentifierNode('input'), [], line_number=1)
    assign1 = AssignmentNode('username', input_call, line_number=1)

    concat = BinaryExpressionNode(
        StringLiteralNode("SELECT * FROM users WHERE name = "),
        '+',
        IdentifierNode('username'),
        line_number=2
    )
    assign2 = AssignmentNode('query', concat, line_number=2)

    execute_call = FunctionCallNode(
        MemberAccessNode(IdentifierNode('cursor'), 'execute'),
        [IdentifierNode('query')],
        line_number=3
    )

    return "Vulnerable - String Concatenation", ProgramNode([assign1, assign2, execute_call])


def vulnerable_format_program():
    input_call = FunctionCallNode(IdentifierNode('input'), [], line_number=1)
    assign1 = AssignmentNode('user_id', input_call, line_number=1)

    format_expr = BinaryExpressionNode(
        StringLiteralNode("SELECT * FROM users WHERE id = %s"),
        '%',
        IdentifierNode('user_id'),
        line_number=2
    )

    assign2 = AssignmentNode('query', format_expr, line_number=2)

    execute_call = FunctionCallNode(
        MemberAccessNode(IdentifierNode('cursor'), 'execute'),
        [IdentifierNode('query')],
        line_number=3
    )

    return "Vulnerable - Format String", ProgramNode([assign1, assign2, execute_call])


def safe_parameterized_program():
    input_call = FunctionCallNode(IdentifierNode('input'), [], line_number=1)
    assign1 = AssignmentNode('user_id', input_call, line_number=1)

    assign2 = AssignmentNode(
        'query',
        StringLiteralNode("SELECT * FROM users WHERE id = ?"),
        line_number=2
    )

    execute_call = FunctionCallNode(
        MemberAccessNode(IdentifierNode('cursor'), 'execute'),
        [IdentifierNode('query'), IdentifierNode('user_id')],
        line_number=3
    )

    return "Safe - Parameterized Query", ProgramNode([assign1, assign2, execute_call])

def safe_sanitized_program():
    input_call = FunctionCallNode(IdentifierNode('input'), [], line_number=1)
    sanitize_call = FunctionCallNode(
        IdentifierNode('sanitize'),
        [input_call],
        line_number=2
    )

    assign1 = AssignmentNode('username', sanitize_call, line_number=2)

    concat = BinaryExpressionNode(
        StringLiteralNode("SELECT * FROM users WHERE name = "),
        '+',
        IdentifierNode('username'),
        line_number=3
    )

    assign2 = AssignmentNode('query', concat, line_number=3)

    execute_call = FunctionCallNode(
        MemberAccessNode(IdentifierNode('cursor'), 'execute'),
        [IdentifierNode('query')],
        line_number=4
    )

    return "Safe - Sanitized Input", ProgramNode([assign1, assign2, execute_call])
