from fastapi import APIRouter, UploadFile, File, Form
from pydantic import BaseModel
import ast

from ..services.scanner import run_static_analysis
from ..services.explainer import explain_vulnerabilities

router = APIRouter()

class AnalysisResult(BaseModel):
    type: str
    line: int
    code: str
    explanation: str

@router.post("/")
async def analyze_code(file=None, code=None):
    if file:
        contents = await file.read()
        code_str = contents.decode()
    elif code:
        code_str = code
    else:
        return {"error": "No code provided"}
    
    try:
        tree = ast.parse(code_str)
    except Exception as e:
        return {"error": f"Invalid Python code: {str(e)}"}
    
    raw_vulns = run_static_analysis(tree, code_str)
    explained = explain_vulnerabilities(raw_vulns)

    return {"vulnerabilities": explained}