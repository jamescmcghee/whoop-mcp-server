import Database from 'better-sqlite3';
import path from 'node:path';

export interface Hard75Config {
  key: string;
  value: string;
}

export interface Hard75Day {
  id: number;
  date: string;
  day_number: number;
  workout1_done: number;
  workout1_outdoor: number;
  workout1_duration: number;
  workout2_done: number;
  workout2_outdoor: number;
  workout2_duration: number;
  water_oz: number;
  diet_followed: number;
  no_alcohol: number;
  reading_done: number;
  reading_pages: number;
  photo_taken: number;
  all_tasks_complete: number;
}

export interface FoodEntry {
  id: number;
  date: string;
  barcode: string | null;
  product_name: string;
  brand: string | null;
  calories: number | null;
  protein_g: number | null;
  carbs_g: number | null;
  fat_g: number | null;
  serving_size: string | null;
  quantity: number;
  meal_type: string;
  created_at: string;
}

export interface ReadingSession {
  id: number;
  date: string;
  topic: string;
  article_title: string | null;
  pages_read: number;
  completed: number;
  created_at: string;
}

export interface ProgressPhoto {
  id: number;
  date: string;
  day_number: number;
  filename: string;
  filepath: string;
  notes: string | null;
  created_at: string;
}

export class Hard75Database {
  private db: Database.Database;

  constructor(dbPath: string = 'hard75.db') {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS hard75_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS hard75_days (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL UNIQUE,
        day_number INTEGER DEFAULT 0,
        workout1_done INTEGER DEFAULT 0,
        workout1_outdoor INTEGER DEFAULT 0,
        workout1_duration INTEGER DEFAULT 0,
        workout2_done INTEGER DEFAULT 0,
        workout2_outdoor INTEGER DEFAULT 0,
        workout2_duration INTEGER DEFAULT 0,
        water_oz INTEGER DEFAULT 0,
        diet_followed INTEGER DEFAULT 0,
        no_alcohol INTEGER DEFAULT 0,
        reading_done INTEGER DEFAULT 0,
        reading_pages INTEGER DEFAULT 0,
        photo_taken INTEGER DEFAULT 0,
        all_tasks_complete INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS food_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        barcode TEXT,
        product_name TEXT NOT NULL,
        brand TEXT,
        calories REAL,
        protein_g REAL,
        carbs_g REAL,
        fat_g REAL,
        serving_size TEXT,
        quantity REAL DEFAULT 1,
        meal_type TEXT DEFAULT 'snack',
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS reading_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        topic TEXT NOT NULL,
        article_title TEXT,
        pages_read INTEGER DEFAULT 0,
        completed INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS progress_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        day_number INTEGER DEFAULT 0,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_hard75_days_date ON hard75_days(date);
      CREATE INDEX IF NOT EXISTS idx_food_log_date ON food_log(date);
      CREATE INDEX IF NOT EXISTS idx_reading_sessions_date ON reading_sessions(date);
      CREATE INDEX IF NOT EXISTS idx_progress_photos_date ON progress_photos(date);
    `);
  }

  // Config
  getConfig(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM hard75_config WHERE key = ?').get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  setConfig(key: string, value: string): void {
    this.db.prepare('INSERT OR REPLACE INTO hard75_config (key, value) VALUES (?, ?)').run(key, value);
  }

  getAllConfig(): Record<string, string> {
    const rows = this.db.prepare('SELECT key, value FROM hard75_config').all() as Hard75Config[];
    return Object.fromEntries(rows.map(r => [r.key, r.value]));
  }

  // Days
  getTodayEntry(date: string, dayNumber: number): Hard75Day {
    this.db.prepare(
      'INSERT OR IGNORE INTO hard75_days (date, day_number) VALUES (?, ?)'
    ).run(date, dayNumber);
    return this.db.prepare('SELECT * FROM hard75_days WHERE date = ?').get(date) as Hard75Day;
  }

  updateDayEntry(date: string, fields: Partial<Omit<Hard75Day, 'id' | 'date' | 'all_tasks_complete'>>): Hard75Day {
    const allowed = [
      'day_number', 'workout1_done', 'workout1_outdoor', 'workout1_duration',
      'workout2_done', 'workout2_outdoor', 'workout2_duration', 'water_oz',
      'diet_followed', 'no_alcohol', 'reading_done', 'reading_pages', 'photo_taken'
    ];
    const keys = Object.keys(fields).filter(k => allowed.includes(k));
    if (keys.length > 0) {
      const setClauses = keys.map(k => `${k} = ?`).join(', ');
      const values = keys.map(k => (fields as Record<string, unknown>)[k]);
      this.db.prepare(`UPDATE hard75_days SET ${setClauses} WHERE date = ?`).run(...values, date);
    }
    this.updateCompletionStatus(date);
    return this.db.prepare('SELECT * FROM hard75_days WHERE date = ?').get(date) as Hard75Day;
  }

  private updateCompletionStatus(date: string): void {
    const row = this.db.prepare('SELECT * FROM hard75_days WHERE date = ?').get(date) as Hard75Day | undefined;
    if (!row) return;
    const complete = (
      row.workout1_done === 1 &&
      row.workout2_done === 1 &&
      (row.workout1_outdoor === 1 || row.workout2_outdoor === 1) &&
      row.water_oz >= 128 &&
      row.diet_followed === 1 &&
      row.no_alcohol === 1 &&
      row.reading_done === 1 &&
      row.reading_pages >= 10 &&
      row.photo_taken === 1
    ) ? 1 : 0;
    this.db.prepare('UPDATE hard75_days SET all_tasks_complete = ? WHERE date = ?').run(complete, date);
  }

  getAllDays(): Hard75Day[] {
    return this.db.prepare('SELECT * FROM hard75_days ORDER BY date ASC').all() as Hard75Day[];
  }

  getStreak(): number {
    const rows = this.db.prepare(
      'SELECT date, all_tasks_complete FROM hard75_days ORDER BY date DESC'
    ).all() as { date: string; all_tasks_complete: number }[];
    let streak = 0;
    const today = new Date().toISOString().slice(0, 10);
    for (const row of rows) {
      if (row.date > today) continue;
      if (row.all_tasks_complete === 1) {
        streak++;
      } else {
        break;
      }
    }
    return streak;
  }

  // Food log
  getFoodLog(date: string): FoodEntry[] {
    return this.db.prepare('SELECT * FROM food_log WHERE date = ? ORDER BY created_at ASC').all(date) as FoodEntry[];
  }

  addFoodEntry(entry: Omit<FoodEntry, 'id' | 'created_at'>): FoodEntry {
    const result = this.db.prepare(`
      INSERT INTO food_log (date, barcode, product_name, brand, calories, protein_g, carbs_g, fat_g, serving_size, quantity, meal_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.date, entry.barcode, entry.product_name, entry.brand,
      entry.calories, entry.protein_g, entry.carbs_g, entry.fat_g,
      entry.serving_size, entry.quantity, entry.meal_type
    );
    return this.db.prepare('SELECT * FROM food_log WHERE id = ?').get(result.lastInsertRowid) as FoodEntry;
  }

  deleteFoodEntry(id: number): boolean {
    const result = this.db.prepare('DELETE FROM food_log WHERE id = ?').run(id);
    return result.changes > 0;
  }

  // Reading sessions
  getReadingSessions(date: string): ReadingSession[] {
    return this.db.prepare('SELECT * FROM reading_sessions WHERE date = ? ORDER BY created_at ASC').all(date) as ReadingSession[];
  }

  addReadingSession(session: Omit<ReadingSession, 'id' | 'created_at'>): ReadingSession {
    const result = this.db.prepare(`
      INSERT INTO reading_sessions (date, topic, article_title, pages_read, completed)
      VALUES (?, ?, ?, ?, ?)
    `).run(session.date, session.topic, session.article_title, session.pages_read, session.completed);
    return this.db.prepare('SELECT * FROM reading_sessions WHERE id = ?').get(result.lastInsertRowid) as ReadingSession;
  }

  markReadingComplete(date: string, topic: string, articleTitle: string, pagesRead: number): void {
    this.db.prepare(`
      INSERT INTO reading_sessions (date, topic, article_title, pages_read, completed) VALUES (?, ?, ?, ?, 1)
      ON CONFLICT DO NOTHING
    `).run(date, topic, articleTitle, pagesRead);
    this.db.prepare(
      'UPDATE hard75_days SET reading_done = 1, reading_pages = ? WHERE date = ?'
    ).run(pagesRead, date);
    this.updateCompletionStatus(date);
  }

  // Progress photos
  getAllPhotos(): ProgressPhoto[] {
    return this.db.prepare('SELECT * FROM progress_photos ORDER BY date DESC').all() as ProgressPhoto[];
  }

  addPhoto(photo: Omit<ProgressPhoto, 'id' | 'created_at'>): ProgressPhoto {
    const result = this.db.prepare(`
      INSERT INTO progress_photos (date, day_number, filename, filepath, notes)
      VALUES (?, ?, ?, ?, ?)
    `).run(photo.date, photo.day_number, photo.filename, photo.filepath, photo.notes);
    this.db.prepare(
      'UPDATE hard75_days SET photo_taken = 1 WHERE date = ?'
    ).run(photo.date);
    this.updateCompletionStatus(photo.date);
    return this.db.prepare('SELECT * FROM progress_photos WHERE id = ?').get(result.lastInsertRowid) as ProgressPhoto;
  }

  deletePhoto(id: number): ProgressPhoto | null {
    const photo = this.db.prepare('SELECT * FROM progress_photos WHERE id = ?').get(id) as ProgressPhoto | undefined;
    if (!photo) return null;
    this.db.prepare('DELETE FROM progress_photos WHERE id = ?').run(id);
    return photo;
  }

  close(): void {
    this.db.close();
  }
}
