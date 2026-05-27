import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { Hard75Database } from './hard75-database.js';
import { createHabitsRouter } from './routes/habits.js';
import { createFoodRouter } from './routes/food.js';
import { createReadingRouter } from './routes/reading.js';
import { createPhotosRouter } from './routes/photos.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure upload directory exists
mkdirSync('uploads/progress-photos', { recursive: true });

const db = new Hard75Database(process.env.HARD75_DB_PATH ?? 'hard75.db');
const app = express();
const PORT = Number(process.env.HARD75_PORT ?? 3001);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve uploaded photos
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../public/hard75')));

// API routes
app.use('/api/habits', createHabitsRouter(db));
app.use('/api/food', createFoodRouter(db));
app.use('/api/reading', createReadingRouter(db));
app.use('/api/photos', createPhotosRouter(db));

// Config endpoints
app.get('/api/config', (_req, res) => {
  res.json(db.getAllConfig());
});

app.post('/api/config', (req, res) => {
  const { start_date, ...rest } = req.body as Record<string, string>;
  if (start_date) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start_date)) {
      res.status(400).json({ error: 'start_date must be YYYY-MM-DD' });
      return;
    }
    db.setConfig('start_date', start_date);
  }
  for (const [k, v] of Object.entries(rest)) {
    if (typeof v === 'string') db.setConfig(k, v);
  }
  res.json(db.getAllConfig());
});

// Streak endpoint
app.get('/api/streak', (_req, res) => {
  res.json({ streak: db.getStreak() });
});

// SPA fallback — serve index.html for unknown routes
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '../public/hard75/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Hard 75 Tracker running at http://localhost:${PORT}`);
});
