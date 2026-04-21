"""
Flask API backend for the SQL Injection Detection System
"""

import sys
import os
import json
import tempfile
import traceback
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unified_types import SymbolTable
from module1_input_detection import InputDetectionModule
from module2_rule_engine import RuleEngineModule
from module3_warning_logic import WarningDecisionLogic
from ast_traverser import ASTTraverser
from python_ast_bridge import PythonASTBridge
from ai_healer import AICodeHealer
from ml_model import get_ml_model

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)


def analyze_file(filepath: str) -> dict:
    """Run the full analysis pipeline on a given file and return structured results."""
    bridge = PythonASTBridge()
    ast_root = bridge.parse_file(filepath)

    symbol_table = SymbolTable()
    input_detector = InputDetectionModule(symbol_table)
    rule_engine = RuleEngineModule(symbol_table)
    warning_logic = WarningDecisionLogic(symbol_table)

    traverser = ASTTraverser(input_detector, rule_engine, warning_logic, symbol_table)
    stats = traverser.analyze(ast_root)

    # Build symbol table snapshot
    symbol_snapshot = {
        var: state.value if hasattr(state, 'value') else str(state)
        for var, state in symbol_table.get_all_variables().items()
    }

    # Parse JSON report
    report_json = json.loads(warning_logic.generate_json_report())

    # Read source code for AI healing
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()

    # Generate AI-powered fixes using rule-based healer
    healer = AICodeHealer()
    fixes_result = healer.generate_batch_fixes(report_json["vulnerabilities"], source_code)

    # Generate ML-powered fixes (can handle ANY code input)
    ml_model = get_ml_model()
    ml_fixes_result = ml_model.batch_analyze(report_json["vulnerabilities"], source_code)

    return {
        "success": True,
        "filename": os.path.basename(filepath),
        "summary": report_json["summary"],
        "vulnerabilities": report_json["vulnerabilities"],
        "symbol_table": symbol_snapshot,
        "stats": stats,
        "source_code": source_code,
        "fixes": fixes_result.get("fixes", []),
        "fixed_code": fixes_result.get("fixed_code", source_code),
        "ml_fixes": ml_fixes_result.get("fixes", []),
        "ml_fixed_code": ml_fixes_result.get("fixed_code", source_code),
        "ml_model_info": {
            "type": ml_fixes_result.get("model_type", "ML-Based"),
            "capabilities": ml_fixes_result.get("capabilities", "Handles any input")
        }
    }


@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    uploaded = request.files['file']
    if uploaded.filename == '':
        return jsonify({"success": False, "error": "Empty filename"}), 400

    if not uploaded.filename.endswith('.py'):
        return jsonify({"success": False, "error": "Only .py files are supported"}), 400

    # Write to a temp file
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='wb') as tmp:
        uploaded.save(tmp)
        tmp_path = tmp.name

    try:
        result = analyze_file(tmp_path)
        result["filename"] = uploaded.filename
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500
    finally:
        os.unlink(tmp_path)


if __name__ == '__main__':
    print("\n[*] SQL Injection Detector - Web UI")
    print("[*] Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
