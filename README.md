# Trojan
nwHacks 2026

Multi-agent security vulnerability scanner.

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Development Server
```bash
npm run dev
```

The server will start at `http://localhost:3000`

### 3. Test the API

**Option A: Using curl**
```bash
curl -X POST http://localhost:3000/api/clone \
  -H "Content-Type: application/json" \
  -d '{"githubUrl": "https://github.com/vercel/next.js"}'
```

**Option B: Using a REST client** (Postman, Insomnia, etc.)
- Method: `POST`
- URL: `http://localhost:3000/api/clone`
- Headers: `Content-Type: application/json`
- Body:
```json
{
  "githubUrl": "https://github.com/vercel/next.js"
}
```

**Option C: Using the browser**
Visit `http://localhost:3000` to see the homepage with instructions.

## API Endpoint

### POST `/api/clone`

Clones a GitHub repository locally.

**Request Body:**
```json
{
  "githubUrl": "https://github.com/user/repo"
}
```

**Response:**
```json
{
  "success": true,
  "sessionId": "uuid-here",
  "repoPath": "/tmp/trojan_repos/uuid-here",
  "message": "Repository cloned successfully"
}
```

**Supported URL formats:**
- `https://github.com/user/repo`
- `github.com/user/repo`
- `git@github.com:user/repo.git`
