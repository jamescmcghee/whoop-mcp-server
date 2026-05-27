import { Router } from 'express';
import { createRequire } from 'node:module';
import path from 'node:path';
import { unlink } from 'node:fs/promises';
import { Hard75Database } from '../hard75-database.js';

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const multer = require('multer') as any;

export function createPhotosRouter(db: Hard75Database): Router {
  const router = Router();

  const storage = multer.diskStorage({
    destination: 'uploads/progress-photos/',
    filename: (_req: unknown, file: { originalname: string }, cb: (err: null, name: string) => void) => {
      const ext = path.extname(file.originalname) || '.jpg';
      cb(null, `photo_${Date.now()}${ext}`);
    },
  });

  const upload = multer({
    storage,
    limits: { fileSize: 20 * 1024 * 1024 },
    fileFilter: (_req: unknown, file: { mimetype: string }, cb: (err: null, ok: boolean) => void) => {
      cb(null, /^image\//.test(file.mimetype));
    },
  });

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

  router.post('/upload', upload.single('photo'), (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: 'No image file provided' });
      return;
    }
    const date = (req.body.date as string) || todayDate();
    const startDate = db.getConfig('start_date');
    const dayNumber = getDayNumber(startDate);
    const notes = (req.body.notes as string) || null;

    const photo = db.addPhoto({
      date,
      day_number: dayNumber,
      filename: req.file.filename,
      filepath: `/uploads/progress-photos/${req.file.filename}`,
      notes,
    });
    res.status(201).json(photo);
  });

  router.get('/', (_req, res) => {
    const photos = db.getAllPhotos();
    res.json(photos);
  });

  router.delete('/:id', async (req, res) => {
    const id = Number(req.params.id);
    const photo = db.deletePhoto(id);
    if (!photo) {
      res.status(404).json({ error: 'Photo not found' });
      return;
    }
    try {
      await unlink(`uploads/progress-photos/${photo.filename}`);
    } catch {
      // file may already be gone
    }
    res.json({ deleted: true });
  });

  return router;
}
