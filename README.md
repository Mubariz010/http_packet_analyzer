# Burp AI Analyzer

AI-powered HTTP traffic analyzer for Burp Suite using Claude.

## Requirements
- Docker + Docker Compose
- Burp Suite (any edition)
- Anthropic API key

## Setup

### 1. Start the AI server
```bash
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
docker compose up --build
```

### 2. Load the Burp extension
```
Burp → Extensions → Add → Python → burp_ai_extension.py
```
Requires Jython standalone JAR configured in Burp → Extensions → Options.

### 3. Browse your target
Findings appear at `http://127.0.0.1:8719/ui`
Architecture map at `http://127.0.0.1:8719/arch`

## Features
- Passive AI analysis of every HTTP response
- Deep analysis on demand (right-click in Burp)
- Application architecture map
- Cost tracking
