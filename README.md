# Burp AI Analyzer

AI-powered HTTP traffic analyzer for Burp Suite using Claude.

### Requirements
- Docker & Docker Compose
- Burp Suite (any edition)
- Jython standalone JAR ([download here](https://www.jython.org/download))
- Anthropic API key ([get one here](https://console.anthropic.com))

### 1. Clone the repository
```bash
git clone https://github.com/Mubariz010/http_packet_analyzer.git
cd http_packet_analyzer
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate        # Linux/Mac/WSL
venv\Scripts\activate           # Windows
```


### 3. Set up environment
```bash
cp .env.example .env
# Add your API key inside `.env`:
nano .env
```

### 4. Start the server
```bash
docker compose up --build
```

### 5. Browse your target
Findings appear at `http://127.0.0.1:8719/ui`
Architecture map at `http://127.0.0.1:8719/arch`

## Features
- Passive AI analysis of every HTTP response
- Deep analysis on demand (right-click in Burp)
- Application architecture map
- Cost tracking
