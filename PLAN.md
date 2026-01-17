# Trojan - Multi-Agent Security Scanner

## 🎯 Concept

A multi-agent system that autonomously finds security vulnerabilities in code. Users paste a GitHub URL, and agents work together to discover issues in real-time.

**The "Wow" Factor**: Real-time dashboard showing agents finding vulnerabilities live as they work.

---

## 🤖 Agents

### Agent Pipeline

```
GitHub URL → Clone Repo
    ↓
[Structure Analyzer] → Maps files and functions
    ↓
[Suspicious File Identifier] → Finds security-sensitive code
    ↓
[Specialist Agents] → Test for specific vulnerabilities
    ├─ XSS Specialist
    ├─ SQL Injection Specialist
    ├─ Authentication Specialist
    ├─ Authorization Specialist
    └─ (more can be added)
    ↓
Findings streamed LIVE to frontend
```

### Agent Details

**1. Structure Analyzer**
- Scans repository structure
- Lists all functions/endpoints
- Detects technology stack

**2. Suspicious File Identifier**
- Identifies security-sensitive areas (login, auth, database queries, file uploads)
- Prioritizes what to test first

**3. Specialist Agents**
- Each tests for one type of vulnerability
- Stream findings to frontend immediately when found
- Examples: XSS, SQL Injection, Authentication flaws, etc.

---

## 🏗️ Tech Stack

### Backend
- **Python** with **LangGraph** (agent orchestration)
- **FastAPI** (REST API)
- **WebSockets** (real-time streaming)
- **Supabase** (database for findings)

### Frontend
- **React/Next.js** (dashboard)
- **WebSocket client** (real-time updates)
- **Monaco Editor** (code viewing)

### Storage
- **Temporary**: Cloned repos stored in `/tmp/trojan_repos/` during analysis, deleted after
- **Permanent**: Only vulnerability findings stored in Supabase (not full code)

---

## 📥 Input Method

**GitHub URL** (start here)
- User pastes GitHub repository URL
- Backend clones repo using `git clone`
- Works for public repositories
- Simple to implement

**Optional later**: Manual file upload, GitHub OAuth for private repos

---

## 💾 How It Works

1. **User provides GitHub URL** → Backend clones to temp directory
2. **Structure Analyzer** → Maps codebase structure
3. **Suspicious Identifier** → Finds security-sensitive functions
4. **Specialist Agents** → Test in parallel, stream findings live
5. **Frontend Dashboard** → Shows vulnerabilities as they're discovered
6. **Cleanup** → Temp directory deleted, findings saved to Supabase

---

## 📊 Frontend Dashboard

- **Live vulnerability feed** - New findings appear instantly
- **Agent activity log** - See what each agent is doing
- **Vulnerability list** - Severity, location, description
- **Code viewer** - See affected code snippets
- **Real-time counter** - Watch vulnerability count grow

---

## 🔴 Live Streaming

**Critical**: Vulnerabilities must stream to frontend immediately when found.

**Event Types**:
- `vulnerability_found` - New vulnerability discovered
- `agent_thought` - Agent reasoning/logs
- `agent_status` - Agent state changes

**Example Event**:
```json
{
  "event_type": "vulnerability_found",
  "agent": "XSS_Specialist",
  "vulnerability": {
    "type": "Cross-Site Scripting (XSS)",
    "severity": "high",
    "location": {"file": "src/auth/login.js", "line": 42},
    "description": "User input rendered without sanitization",
    "proof_of_concept": "<script>alert('XSS')</script>"
  }
}
```

---

## 📋 Implementation Phases

### Phase 1: Core
- [ ] Project setup
- [ ] Structure Analyzer agent
- [ ] Suspicious File Identifier agent
- [ ] Basic LangGraph workflow
- [ ] Supabase database setup

### Phase 2: Security Testing
- [ ] 2-3 specialist agents (XSS, SQLi)
- [ ] Vulnerability detection logic
- [ ] Payload generation

### Phase 3: Frontend
- [ ] WebSocket streaming
- [ ] Dashboard UI
- [ ] Real-time vulnerability feed
- [ ] Agent activity display

### Phase 4: Polish
- [ ] Additional specialist agents
- [ ] Code diff visualization
- [ ] Error handling
- [ ] UI improvements

---

## 🗄️ Database Schema (Supabase)

```sql
-- Analysis sessions
CREATE TABLE analysis_sessions (
  id UUID PRIMARY KEY,
  github_url TEXT,
  status TEXT, -- 'running', 'completed', 'failed'
  created_at TIMESTAMP
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
  id UUID PRIMARY KEY,
  session_id UUID REFERENCES analysis_sessions(id),
  type TEXT, -- 'XSS', 'SQLi', etc.
  severity TEXT,
  file_path TEXT,
  line_number INTEGER,
  code_snippet TEXT,
  description TEXT,
  proof_of_concept TEXT
);
```

---

## 🔐 Security Notes

- Run agents in isolated environments
- Only test with permission
- Don't store full repository code (privacy)
- Clean up temp files after analysis

---

## 📝 Key Points

- **LangGraph** handles all agent coordination (no message queue needed)
- **Live streaming** is essential - vulnerabilities appear as found
- **Temporary storage** - repos deleted after analysis
- **Extensible** - easy to add new specialist agents
- **Parallel execution** - multiple agents work simultaneously
