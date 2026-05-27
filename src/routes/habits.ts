import { Router } from 'express';
import { Hard75Database } from '../hard75-database.js';

export function createHabitsRouter(db: Hard75Database): Router {
  const router = Router();

  function todayDate(): string {
    return new Date().toISOString().slice(0, 10);
  }

  function getDayNumber(startDate: string | null): number {
    if (!startDate) return 0;
    const start = new Date(startDate);
    const today = new Date(todayDate());
    const diff = Math.floor((today.getTime() - start.getTime()) / 86400000);
    return Math.max(1, diff + 1);
  }

  router.get('/today', (req, res) => {
    const date = (req.query.date as string) || todayDate();
    const startDate = db.getConfig('start_date');
    const dayNumber = getDayNumber(startDate);
    const entry = db.getTodayEntry(date, dayNumber);
    const streak = db.getStreak();
    res.json({ ...entry, streak, start_date: startDate });
  });

  router.post('/today', (req, res) => {
    const date = (req.body.date as string) || todayDate();
    const {
      workout1_done, workout1_outdoor, workout1_duration,
      workout2_done, workout2_outdoor, workout2_duration,
      water_oz, diet_followed, no_alcohol,
      reading_done, reading_pages, photo_taken
    } = req.body;

    const startDate = db.getConfig('start_date');
    const dayNumber = getDayNumber(startDate);

    // Ensure row exists
    db.getTodayEntry(date, dayNumber);

    const fields: Record<string, unknown> = {};
    if (workout1_done !== undefined) fields.workout1_done = Number(workout1_done);
    if (workout1_outdoor !== undefined) fields.workout1_outdoor = Number(workout1_outdoor);
    if (workout1_duration !== undefined) fields.workout1_duration = Number(workout1_duration);
    if (workout2_done !== undefined) fields.workout2_done = Number(workout2_done);
    if (workout2_outdoor !== undefined) fields.workout2_outdoor = Number(workout2_outdoor);
    if (workout2_duration !== undefined) fields.workout2_duration = Number(workout2_duration);
    if (water_oz !== undefined) fields.water_oz = Number(water_oz);
    if (diet_followed !== undefined) fields.diet_followed = Number(diet_followed);
    if (no_alcohol !== undefined) fields.no_alcohol = Number(no_alcohol);
    if (reading_done !== undefined) fields.reading_done = Number(reading_done);
    if (reading_pages !== undefined) fields.reading_pages = Number(reading_pages);
    if (photo_taken !== undefined) fields.photo_taken = Number(photo_taken);

    const updated = db.updateDayEntry(date, fields);
    const streak = db.getStreak();
    res.json({ ...updated, streak });
  });

  router.get('/history', (_req, res) => {
    const days = db.getAllDays();
    res.json(days);
  });

  return router;
}
