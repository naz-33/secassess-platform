"""Prompt templates for AI-assisted security analysis."""

INTERPRET_PROMPT = """
You are a senior penetration tester. Given the raw vulnerability evidence below, explain the underlying technical flaw, potential attack vectors, and exploitability.
Evidence:
{evidence}
"""

PRIORITIZE_PROMPT = """
Analyze the following list of findings within the target context:
{findings}
Rank them by actual risk and operational exploitability.
"""

REMEDIATE_PROMPT = """
Provide clear, actionable code-level and architecture-level remediation advice for the following vulnerability:
{finding}
"""

SUMMARIZE_PROMPT = """
Generate an executive summary of the security posture and findings for the assessment:
{assessment_summary}
"""
