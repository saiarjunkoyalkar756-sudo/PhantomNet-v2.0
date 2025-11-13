import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from io import StringIO

from phantomnet_agent.analyzers.ml_analyzer import MLAnalyzer
from phantomnet_agent.analyzers.rule_based_analyzer import RuleBasedAnalyzer
from phantomnet_agent.analyzers.command_injection_analyzer import CommandInjectionAnalyzer
from phantomnet_agent.ai_analyzer import analyze_attack

@pytest.fixture
def mock_csv():
    csv_data = "payload,type\n<script>alert('XSS')</script>,XSS\nSELECT * FROM users,SQL Injection"
    return StringIO(csv_data)

@patch('pandas.read_csv')
def test_ml_analyzer(mock_read_csv, mock_csv):
    mock_read_csv.return_value = pd.read_csv(mock_csv)
    analyzer = MLAnalyzer()
    assert analyzer.analyze("<script>alert('XSS')</script>") == "XSS"
    assert analyzer.analyze("SELECT * FROM users") == "SQL Injection"

def test_rule_based_analyzer():
    analyzer = RuleBasedAnalyzer()
    assert analyzer.analyze("<script>alert('XSS')</script>") == "XSS"
    assert analyzer.analyze("1' or '1'='1") == "SQL Injection"
    assert analyzer.analyze("../../etc/passwd") == "Directory Traversal"
    assert analyzer.analyze("nmap -sS 127.0.0.1") == "Port Scan"
    assert analyzer.analyze("admin:admin") == "Brute Force"
    assert analyzer.analyze("some other payload") is None

def test_command_injection_analyzer():
    analyzer = CommandInjectionAnalyzer()
    assert analyzer.analyze("; ls -la") == "Command Injection"
    assert analyzer.analyze("| whoami") == "Command Injection"
    assert analyzer.analyze("&& cat /etc/passwd") == "Command Injection"
    assert analyzer.analyze("`uname -a`") == "Command Injection"
    assert analyzer.analyze("$(ifconfig)") == "Command Injection"
    assert analyzer.analyze("some other payload") is None

# This test will use the already loaded analyzers from the ai_analyzer module
@patch('phantomnet_agent.analyzers.ml_analyzer.MLAnalyzer.analyze')
@patch('phantomnet_agent.analyzers.rule_based_analyzer.RuleBasedAnalyzer.analyze')
@patch('phantomnet_agent.analyzers.command_injection_analyzer.CommandInjectionAnalyzer.analyze')
def test_analyze_attack(mock_cmd_inj_analyze, mock_rule_based_analyze, mock_ml_analyze):
    mock_ml_analyze.return_value = "XSS"
    mock_rule_based_analyze.return_value = None
    mock_cmd_inj_analyze.return_value = None
    assert analyze_attack("test payload") == "XSS"

    mock_ml_analyze.return_value = None
    mock_rule_based_analyze.return_value = "SQL Injection"
    mock_cmd_inj_analyze.return_value = None
    assert analyze_attack("test payload") == "SQL Injection"

    mock_ml_analyze.return_value = None
    mock_rule_based_analyze.return_value = None
    mock_cmd_inj_analyze.return_value = "Command Injection"
    assert analyze_attack("test payload") == "Command Injection"

    mock_ml_analyze.return_value = None
    mock_rule_based_analyze.return_value = None
    mock_cmd_inj_analyze.return_value = None
    assert analyze_attack("test payload") == "Unknown"