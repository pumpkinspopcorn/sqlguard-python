"""
Main - SQL Injection Detector
Usage:
    python main.py                  # run built-in demo cases
    python main.py <file.py>        # analyse a real Python source file
"""

import sys
import os

from unified_types import *
from module1_input_detection import InputDetectionModule
from module2_rule_engine import RuleEngineModule
from module3_warning_logic import WarningDecisionLogic
from ast_traverser import ASTTraverser
from python_ast_bridge import PythonASTBridge

import demo_programs


def run_demo(title, ast_root):
    print("\n" + "="*80)
    print(f"DEMO CASE: {title}")
    print("="*80)

    symbol_table = SymbolTable()

    input_detector = InputDetectionModule(symbol_table)
    rule_engine    = RuleEngineModule(symbol_table)
    warning_logic  = WarningDecisionLogic(symbol_table)

    traverser = ASTTraverser(
        input_detector,
        rule_engine,
        warning_logic,
        symbol_table
    )

    print("\n>> Running Analysis...\n")

    stats = traverser.analyze(ast_root)

    print("\n>> Symbol Table State:")
    for var, state in symbol_table.get_all_variables().items():
        print(f"   {var} -> {state}")

    print("\n>> Detailed Vulnerability Report:")
    print(warning_logic.generate_text_report())

    print("\n>> JSON Report:")
    print(warning_logic.generate_json_report())

    print("\n>> Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "="*80 + "\n")


def run_file_mode(filepath):
    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    print(f"\n[*] Analysing file: {filepath}\n")

    bridge   = PythonASTBridge()
    ast_root = bridge.parse_file(filepath)

    title = f"File: {os.path.basename(filepath)}"
    run_demo(title, ast_root)


def run_demo_mode():
    demos = [
        demo_programs.vulnerable_concat_program(),
        demo_programs.vulnerable_format_program(),
        demo_programs.safe_parameterized_program(),
        demo_programs.safe_sanitized_program(),
    ]
    for title, ast in demos:
        run_demo(title, ast)
    print("\n[DONE] Demonstration Complete.\n")


if __name__ == "__main__":

    print("""
+------------------------------------------------------------------------------+
|         WEEK 6 - SQL INJECTION DETECTION SYSTEM                              |
+------------------------------------------------------------------------------+
""")

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in ("--help", "-h"):
            print("Usage:")
            print("  python main.py               # run built-in demo cases")
            print("  python main.py <file.py>     # analyse a Python source file")
        else:
            run_file_mode(arg)
    else:
        run_demo_mode()
