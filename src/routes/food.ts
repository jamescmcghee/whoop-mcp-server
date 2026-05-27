import { Router } from 'express';
import { Hard75Database } from '../hard75-database.js';

interface OpenFoodFactsNutriments {
  'energy-kcal_100g'?: number;
  'energy-kcal'?: number;
  energy_100g?: number;
  proteins_100g?: number;
  carbohydrates_100g?: number;
  fat_100g?: number;
}

interface OpenFoodFactsProduct {
  product_name?: string;
  brands?: string;
  serving_size?: string;
  nutriments?: OpenFoodFactsNutriments;
}

interface OpenFoodFactsResponse {
  status: number;
  product?: OpenFoodFactsProduct;
}

export function createFoodRouter(db: Hard75Database): Router {
  const router = Router();

  function todayDate(): string {
    return new Date().toISOString().slice(0, 10);
  }

  router.get('/barcode/:barcode', async (req, res) => {
    const { barcode } = req.params;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(
        `https://world.openfoodfacts.org/api/v2/product/${encodeURIComponent(barcode)}.json`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': 'Hard75Tracker/1.0' }
        }
      );
      clearTimeout(timeout);

      if (!response.ok || response.status === 404) {
        res.status(404).json({ found: false });
        return;
      }

      const data = await response.json() as OpenFoodFactsResponse;

      if (data.status !== 1 || !data.product) {
        res.status(404).json({ found: false });
        return;
      }

      const p = data.product;
      const n = p.nutriments ?? {};
      const kcal = n['energy-kcal_100g'] ?? n['energy-kcal'] ?? (n.energy_100g ? n.energy_100g / 4.184 : null);

      res.json({
        found: true,
        barcode,
        product_name: p.product_name ?? '',
        brand: p.brands ?? null,
        serving_size: p.serving_size ?? null,
        calories_per_100g: kcal ?? null,
        protein_per_100g: n.proteins_100g ?? null,
        carbs_per_100g: n.carbohydrates_100g ?? null,
        fat_per_100g: n.fat_100g ?? null,
      });
    } catch (err) {
      clearTimeout(timeout);
      if ((err as Error).name === 'AbortError') {
        res.status(504).json({ error: 'Food database lookup timed out' });
      } else {
        res.status(502).json({ error: 'Could not reach food database' });
      }
    }
  });

  router.get('/log', (req, res) => {
    const date = (req.query.date as string) || todayDate();
    const entries = db.getFoodLog(date);
    const totals = entries.reduce(
      (acc, e) => {
        const q = e.quantity ?? 1;
        acc.calories += ((e.calories ?? 0) * q);
        acc.protein_g += ((e.protein_g ?? 0) * q);
        acc.carbs_g += ((e.carbs_g ?? 0) * q);
        acc.fat_g += ((e.fat_g ?? 0) * q);
        return acc;
      },
      { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 }
    );
    res.json({ entries, totals: { ...totals } });
  });

  router.post('/log', (req, res) => {
    const {
      date, barcode, product_name, brand, calories,
      protein_g, carbs_g, fat_g, serving_size, quantity, meal_type
    } = req.body;

    if (!product_name) {
      res.status(400).json({ error: 'product_name is required' });
      return;
    }

    const entry = db.addFoodEntry({
      date: date || todayDate(),
      barcode: barcode ?? null,
      product_name,
      brand: brand ?? null,
      calories: calories != null ? Number(calories) : null,
      protein_g: protein_g != null ? Number(protein_g) : null,
      carbs_g: carbs_g != null ? Number(carbs_g) : null,
      fat_g: fat_g != null ? Number(fat_g) : null,
      serving_size: serving_size ?? null,
      quantity: quantity != null ? Number(quantity) : 1,
      meal_type: meal_type ?? 'snack',
    });
    res.status(201).json(entry);
  });

  router.delete('/log/:id', (req, res) => {
    const id = Number(req.params.id);
    const deleted = db.deleteFoodEntry(id);
    if (!deleted) {
      res.status(404).json({ error: 'Entry not found' });
      return;
    }
    res.json({ deleted: true });
  });

  return router;
}
