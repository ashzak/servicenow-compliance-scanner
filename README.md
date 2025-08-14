# ServiceNow CMDB Compliance Scanner

A comprehensive multi-agent system for scanning ServiceNow CMDB Configuration Items (CIs) and analyzing their OS compliance status, including End-of-Life (EOL) and End-of-Support (EOS) assessment.

## 🔍 Overview

This project uses CrewAI to orchestrate 4 specialized agents that work together to:

1. **Extract CIs** from ServiceNow CMDB
2. **Scan network elements** to detect actual OS versions
3. **Analyze compliance** against EOL/EOS databases
4. **Generate reports** with remediation recommendations

## 🏗️ Architecture

### Core Components

- **ServiceNow Connector** (`servicenow_connector.py`) - CMDB integration
- **Network Scanner** (`network_scanner.py`) - OS detection via Nmap/SSH/SNMP
- **Compliance Analyzer** (`compliance_analyzer.py`) - EOL/EOS analysis
- **CrewAI Orchestration** (`crew.py`, `agents.py`, `tasks.py`) - Multi-agent workflow

### Execution Modes

1. **Demo Mode** - Sample data analysis (no external dependencies)
2. **Standalone Mode** - Direct module execution
3. **CrewAI Mode** - Full multi-agent workflow

## 🚀 Quick Start

### Demo Mode (No Setup Required)
```bash
# Test compliance analysis with sample data
python3 compliance_analyzer.py

# Run demo via main script
python3 main.py --mode demo
```

### Web Interface
```bash
# Start web interface
python3 web_interface.py

# Open browser to http://localhost:8000
```

## 📋 Requirements

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Environment Variables

For full functionality, set these environment variables:

```bash
# ServiceNow Connection
export SERVICENOW_INSTANCE='your-instance.service-now.com'
export SERVICENOW_USERNAME='your-username'
export SERVICENOW_PASSWORD='your-password'

# OpenAI API (for CrewAI agents)
export OPENAI_API_KEY='your-openai-api-key'
```

## 🎯 Usage

### Command Line Interface

```bash
# Check environment setup
python3 main.py --check-env

# Demo mode with sample data
python3 main.py --mode demo

# Standalone mode (requires ServiceNow credentials)
python3 main.py --mode standalone --scope all

# Full CrewAI workflow (requires OpenAI API key)
python3 main.py --mode crewai --scope servers
```

### Web Interface

1. Start the web server: `python3 web_interface.py`
2. Open http://localhost:8000 in your browser
3. Select scan mode and parameters
4. Monitor progress and view results

### Available Scopes

- `all` - All network elements and servers
- `servers` - Server CIs only
- `network` - Network devices only

## 📊 Output Formats

### Compliance Reports

- **JSON** - Complete analysis data with metadata
- **CSV** - Summary table for spreadsheet analysis
- **Web Dashboard** - Interactive results visualization

### Key Metrics

- **Compliance Score** - Overall organizational compliance (0-100%)
- **Risk Assessment** - CRITICAL/HIGH/MEDIUM/LOW classifications
- **EOL/EOS Status** - End-of-life and end-of-support tracking
- **Remediation Plans** - Prioritized action items

## 🔧 Configuration

### ServiceNow CMDB Classes

The scanner targets these CI classes by default:
- `cmdb_ci_computer` - Generic computers
- `cmdb_ci_linux_server` - Linux servers
- `cmdb_ci_win_server` - Windows servers
- `cmdb_ci_router` - Network routers
- `cmdb_ci_switch` - Network switches
- `cmdb_ci_firewall` - Firewall devices

### EOL Database Coverage

- **Windows** - Server 2008-2022, Windows 7-11
- **Linux** - Ubuntu, CentOS, RHEL, SLES
- **Network OS** - Cisco IOS/IOS-XE, Junos

## 🛠️ Development

### Project Structure

```
servicenow-compliance-scanner/
├── agents.py              # CrewAI agent definitions
├── tasks.py               # CrewAI task definitions  
├── crew.py                # Main workflow orchestration
├── servicenow_connector.py # ServiceNow CMDB integration
├── network_scanner.py     # Network OS detection
├── compliance_analyzer.py # EOL/EOS compliance analysis
├── main.py               # Command line interface
├── web_interface.py      # FastAPI web interface
├── demo.py              # Demo and testing script
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

### Testing

```bash
# Run compliance analysis demo
python3 demo.py

# Test individual modules
python3 compliance_analyzer.py
python3 network_scanner.py

# Test web interface
python3 web_interface.py
```

## 📈 Sample Results

### Demo Compliance Summary
- **Total Systems**: 3
- **Compliance Score**: 46%
- **Non-Compliant**: 2 systems
- **Critical Violations**: 5 issues
- **EOL Systems**: 2 systems requiring immediate attention

### Detected Issues
- Windows Server 2008 R2 (EOL: 2020-01-14) - CRITICAL
- Ubuntu 16.04 (EOL: 2021-04-30) - CRITICAL  
- Windows Server 2019 - COMPLIANT

## 🔒 Security Considerations

- Network scanning uses non-intrusive methods
- ServiceNow credentials should have read-only CMDB access
- OpenAI API key is used only for AI analysis, no data sent to external services
- All sensitive data remains within your environment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Submit a pull request

## 📄 License

This project is provided as-is for educational and demonstration purposes.

## 🆘 Support

### Common Issues

1. **Missing Dependencies**: Run `pip install -r requirements.txt`
2. **ServiceNow Connection**: Verify credentials and network access
3. **OpenAI API**: Ensure valid API key for CrewAI features

### Getting Help

- Check the demo mode first: `python3 main.py --mode demo`
- Verify environment: `python3 main.py --check-env`
- Review output files for detailed error messages

---

**Created with CrewAI** - Multi-agent AI workflow orchestration