import express from 'express';
import cors from 'cors';
import {
  analyzeTarget,
  generateHeaderExplanation,
  triageSubdomains,
  analyzeCookiesAI,
  generateFullReport,
  analyzeVulnerabilities,
  askPentestAssistant
} from './src/lib/analyzeServer.ts';

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.post('/api/analyze', async (req, res) => {
  try {
    const result = await analyzeTarget(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/explain-header', async (req, res) => {
  try {
    const result = await generateHeaderExplanation(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/triage-subdomains', async (req, res) => {
  try {
    const result = await triageSubdomains(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/analyze-cookies', async (req, res) => {
  try {
    const result = await analyzeCookiesAI(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/generate-report', async (req, res) => {
  try {
    const result = await generateFullReport(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/analyze-vulnerabilities', async (req, res) => {
  try {
    const result = await analyzeVulnerabilities(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ask-pentest-assistant', async (req, res) => {
  try {
    const result = await askPentestAssistant(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Backend API running on http://localhost:${port}`);
});
