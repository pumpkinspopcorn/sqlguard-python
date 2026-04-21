"""
python_ast_bridge.py  –  Person A's deliverable
================================================
Parses a real .py source file using Python's built-in `ast` module,
then translates the resulting AST into the custom node types defined
in `unified_types.py`, producing a ProgramNode ready for the
existing analysis pipeline (ast_traverser -> modules -> reports).

Supported translations
-----------------------
  ast.Module       -> ProgramNode
  ast.Assign       -> AssignmentNode
  ast.Call         -> FunctionCallNode
  ast.BinOp        -> BinaryExpressionNode
  ast.Name         -> IdentifierNode
  ast.Constant(str)-> StringLiteralNode
  ast.Constant(num)-> NumberLiteralNode
  ast.Attribute    -> MemberAccessNode  (e.g. cursor.execute)
  anything else    -> silently skipped (no crash)
"""

import ast
from unified_types import (
    ProgramNode,
    AssignmentNode,
    FunctionCallNode,
    BinaryExpressionNode,
    IdentifierNode,
    StringLiteralNode,
    NumberLiteralNode,
    MemberAccessNode,
)

# Mapping from Python ast operator types to string symbols
_BINOP_MAP = {
    ast.Add:    '+',
    ast.Sub:    '-',
    ast.Mult:   '*',
    ast.Div:    '/',
    ast.Mod:    '%',
    ast.BitOr:  '|',
    ast.BitAnd: '&',
}


class PythonASTBridge:
    """
    Converts a Python source file into the project's custom AST nodes.

    Usage
    -----
        bridge = PythonASTBridge()
        program_node = bridge.parse_file("my_script.py")
        # program_node is now a ProgramNode ready for ASTTraverser.analyze()
    """

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def parse_file(self, filepath: str) -> ProgramNode:
        """
        Read a .py file and return a ProgramNode built from its statements.

        Parameters
        ----------
        filepath : str
            Absolute or relative path to the Python source file.

        Returns
        -------
        ProgramNode
            Root node compatible with the existing ASTTraverser.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()

        py_tree = ast.parse(source, filename=filepath)
        statements = self._convert_module(py_tree, filepath)
        return ProgramNode(statements)

    def parse_source(self, source: str, filename: str = "<string>") -> ProgramNode:
        """
        Parse an in-memory source string instead of a file.
        Useful for standalone testing.
        """
        py_tree = ast.parse(source, filename=filename)
        statements = self._convert_module(py_tree, filename)
        return ProgramNode(statements)

    # ------------------------------------------------------------------
    # MODULE LEVEL
    # ------------------------------------------------------------------

    def _convert_module(self, module_node: ast.Module, filepath: str) -> list:
        """Convert all top-level statements in the module."""
        statements = []
        for stmt in module_node.body:
            converted = self._convert_statement(stmt, filepath)
            if converted is not None:
                statements.append(converted)
        return statements

    # ------------------------------------------------------------------
    # STATEMENT CONVERSION
    # ------------------------------------------------------------------

    def _convert_statement(self, stmt, filepath: str):
        """
        Dispatch a Python ast statement node to its converter.
        Returns None for unsupported statement types (silently skipped).
        """
        line = getattr(stmt, 'lineno', -1)

        # --- Simple assignment:  x = <expr>  ---
        if isinstance(stmt, ast.Assign):
            return self._convert_assign(stmt, filepath)

        # --- Annotated assignment:  x: int = <expr>  ---
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target_name = self._extract_name(stmt.target)
            if target_name:
                expr = self._convert_expr(stmt.value, filepath)
                if expr:
                    return AssignmentNode(target_name, expr, line_number=line)

        # --- Expression statement:  cursor.execute(...)  ---
        if isinstance(stmt, ast.Expr):
            expr = self._convert_expr(stmt.value, filepath)
            if expr is not None:
                # Wrap bare function calls in a minimal program statement
                # The traverser checks node.type == 'FunctionCall' directly
                expr.file_path = filepath
                return expr

        # Unsupported statement type — skip silently
        return None

    def _convert_assign(self, node: ast.Assign, filepath: str):
        """
        Handle  x = <expr>
        Only handles single-target assignments (a = b),
        not tuple unpacking (a, b = ...).
        """
        if len(node.targets) != 1:
            return None

        target_name = self._extract_name(node.targets[0])
        if not target_name:
            return None

        expr = self._convert_expr(node.value, filepath)
        if expr is None:
            return None

        return AssignmentNode(target_name, expr, line_number=node.lineno)

    
    # EXPRESSION CONVERSION
    

    def _convert_expr(self, node, filepath: str):
        """
        Recursively convert a Python ast expression into a custom node.
        Returns None if the expression type is not supported.
        """
        if node is None:
            return None

        line = getattr(node, 'lineno', -1)

        # --- Variable name:  username  ---
        if isinstance(node, ast.Name):
            n = IdentifierNode(node.id, line_number=line)
            n.file_path = filepath
            return n

        # --- String or number literal ---
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                n = StringLiteralNode(node.value, line_number=line)
                n.file_path = filepath
                return n
            if isinstance(node.value, (int, float)):
                n = NumberLiteralNode(node.value, line_number=line)
                n.file_path = filepath
                return n
            return None  # bytes, None, bool, etc — skip

        # --- Binary operation:  a + b,  "sql" % var,  etc. ---
        if isinstance(node, ast.BinOp):
            op_symbol = _BINOP_MAP.get(type(node.op), '?')
            left  = self._convert_expr(node.left, filepath)
            right = self._convert_expr(node.right, filepath)
            if left is None or right is None:
                return None
            n = BinaryExpressionNode(left, op_symbol, right, line_number=line)
            n.file_path = filepath
            return n

        # --- Function / method call:  cursor.execute(query)  ---
        if isinstance(node, ast.Call):
            return self._convert_call(node, filepath)

        # --- Attribute access:  cursor.execute  (as expression) ---
        if isinstance(node, ast.Attribute):
            obj = self._convert_expr(node.value, filepath)
            if obj is None:
                return None
            n = MemberAccessNode(obj, node.attr, line_number=line)
            n.file_path = filepath
            return n

        # --- f-string: treat as tainted (conservative) ---
        if isinstance(node, ast.JoinedStr):
            # f-strings often embed variables; treat as IdentifierNode
            # so taint analysis can flag them
            n = IdentifierNode('__fstring__', line_number=line)
            n.file_path = filepath
            return n

        # Unsupported expression type
        return None

    def _convert_call(self, node: ast.Call, filepath: str):
        """
        Convert  func(args)  or  obj.method(args)  into a FunctionCallNode.
        """
        line = getattr(node, 'lineno', -1)

        func = self._convert_expr(node.func, filepath)
        if func is None:
            return None

        args = []
        for arg in node.args:
            converted = self._convert_expr(arg, filepath)
            if converted is not None:
                args.append(converted)

        n = FunctionCallNode(func, args, line_number=line)
        n.file_path = filepath
        return n

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _extract_name(self, target) -> str:
        """
        Try to get a simple string name from an assignment target.
        Returns None for complex targets like subscripts or tuples.
        """
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None

    # ------------------------------------------------------------------
    # STANDALONE TEST  (run: python python_ast_bridge.py)
    # ------------------------------------------------------------------

    def _self_test(self):
        """
        Quick smoke-test using inline source strings.
        Run this file directly to verify the bridge works before
        Person B's main.py integration is ready.
        """
        print("=" * 60)
        print("PythonASTBridge – Standalone Test")
        print("=" * 60)

        VULNERABLE = """\
username = input("Enter username: ")
query = "SELECT * FROM users WHERE name = " + username
cursor.execute(query)
"""

        SAFE = """\
user_id = input("Enter ID: ")
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
"""

        for label, src in [("VULNERABLE", VULNERABLE), ("SAFE", SAFE)]:
            print(f"\n[{label}] Source:\n{src}")
            prog = self.parse_source(src, filename=f"<{label.lower()}>")
            print(f"  ProgramNode children ({len(prog.children)}):")
            for child in prog.children:
                print(f"    type={child.type}  line={child.line_number}")
                # Show details for Assignments
                if child.type == 'AssignmentStatement':
                    print(f"      variable='{child.variable}'  expr.type={child.expression.type}")
        print("\n[PASS] Bridge self-test complete.\n")


if __name__ == "__main__":
    PythonASTBridge()._self_test()
