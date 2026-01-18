// Simple WebSocket test server for testing the frontend
// Run with: node test-websocket-server.js
// Then set NEXT_PUBLIC_WS_URL=ws://localhost:8080/ws in your .env.local

const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8080, path: '/ws' });

console.log('🚀 Mock WebSocket server running on ws://localhost:8080/ws');
console.log('📝 Set NEXT_PUBLIC_WS_URL=ws://localhost:8080/ws in your .env.local');

wss.on('connection', (ws, req) => {
  console.log('✅ Client connected');

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      console.log('📨 Received:', data);

      if (data.type === 'start_scan') {
        console.log(`🔍 Starting scan for ${data.repoUrl}`);
        console.log(`📁 Files to scan: ${data.files.length}`);

        // Simulate vulnerability detection after a delay
        setTimeout(() => {
          // Send a test vulnerability for the first file
          if (data.files.length > 0) {
            const firstFile = data.files[0];
            console.log(`⚠️  Sending test vulnerability for ${firstFile.path}`);

            ws.send(JSON.stringify({
              type: 'vulnerability',
              filePath: firstFile.path,
              vulnerability: {
                line: 10,
                type: 'error',
                label: 'Test: Unsafe Code Execution (eval)'
              }
            }));

            // Send another one after a delay
            setTimeout(() => {
              ws.send(JSON.stringify({
                type: 'vulnerability',
                filePath: firstFile.path,
                vulnerability: {
                  line: 25,
                  type: 'warning',
                  label: 'Test: Potential XSS (innerHTML)'
                }
              }));
            }, 2000);
          }

          // Simulate scan completion
          setTimeout(() => {
            console.log('✅ Scan complete');
            ws.send(JSON.stringify({
              type: 'scan_complete'
            }));
          }, 5000);
        }, 1000);
      }
    } catch (error) {
      console.error('❌ Error parsing message:', error);
    }
  });

  ws.on('close', () => {
    console.log('👋 Client disconnected');
  });

  ws.on('error', (error) => {
    console.error('❌ WebSocket error:', error);
  });
});
