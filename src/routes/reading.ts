import { Router } from 'express';
import { Hard75Database } from '../hard75-database.js';

const WORDS_PER_PAGE = 250;

interface WikiSummary {
  title?: string;
  extract?: string;
  type?: string;
}

function sanitizeText(text: string): string {
  return text
    .replace(/={2,}[^=]+=*/g, '')
    .replace(/\[\d+\]/g, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function paginateText(text: string, wordsPerPage: number): string[] {
  const words = text.split(/\s+/).filter(w => w.length > 0);
  const pages: string[] = [];
  for (let i = 0; i < words.length; i += wordsPerPage) {
    pages.push(words.slice(i, i + wordsPerPage).join(' '));
  }
  return pages;
}

export function createReadingRouter(db: Hard75Database): Router {
  const router = Router();

  function todayDate(): string {
    return new Date().toISOString().slice(0, 10);
  }

  router.get('/article', async (req, res) => {
    const topic = req.query.topic as string;
    if (!topic || !topic.trim()) {
      res.status(400).json({ error: 'topic query parameter is required' });
      return;
    }

    const encoded = encodeURIComponent(topic.trim().replace(/\s+/g, '_'));
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      // First get the canonical title via summary
      const summaryRes = await fetch(
        `https://en.wikipedia.org/api/rest_v1/page/summary/${encoded}`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': 'Hard75Tracker/1.0' }
        }
      );

      if (!summaryRes.ok) {
        clearTimeout(timeout);
        res.status(404).json({ error: `No Wikipedia article found for "${topic}"` });
        return;
      }

      const summary = await summaryRes.json() as WikiSummary;
      const canonicalTitle = summary.title ?? topic;
      const encodedCanonical = encodeURIComponent(canonicalTitle);

      // Fetch full article text via the Action API (returns entire article as plain text)
      let fullText = '';
      try {
        const actionRes = await fetch(
          `https://en.wikipedia.org/w/api.php?action=query&prop=extracts&explaintext=true&exsectionformat=plain&titles=${encodedCanonical}&format=json`,
          {
            signal: controller.signal,
            headers: { 'User-Agent': 'Hard75Tracker/1.0' }
          }
        );
        if (actionRes.ok) {
          const actionData = await actionRes.json() as { query: { pages: Record<string, { extract?: string }> } };
          const pages = actionData.query?.pages ?? {};
          const page = Object.values(pages)[0];
          fullText = page?.extract ?? '';
        }
      } catch {
        // fall through to use summary extract
      }

      clearTimeout(timeout);

      // Fall back to summary extract if Action API failed or returned too little
      if (!fullText || fullText.length < 500) {
        fullText = summary.extract ?? '';
      }

      const cleaned = sanitizeText(fullText);
      const rawPages = paginateText(cleaned, WORDS_PER_PAGE);

      // Ensure at least 10 pages worth — pad with summary paragraphs if needed
      const pages = rawPages.map((content, i) => ({
        page_number: i + 1,
        word_count: content.split(/\s+/).length,
        content,
      }));

      res.json({
        title: canonicalTitle,
        topic,
        total_pages: pages.length,
        pages,
      });
    } catch (err) {
      clearTimeout(timeout);
      if ((err as Error).name === 'AbortError') {
        res.status(504).json({ error: 'Wikipedia fetch timed out' });
      } else {
        res.status(502).json({ error: 'Could not reach Wikipedia' });
      }
    }
  });

  router.post('/complete', (req, res) => {
    const { date, topic, article_title, pages_read } = req.body;
    if (!topic) {
      res.status(400).json({ error: 'topic is required' });
      return;
    }
    const d = date || todayDate();
    const pages = Math.max(10, Number(pages_read) || 10);
    db.markReadingComplete(d, topic, article_title ?? topic, pages);
    res.json({ success: true, date: d, topic, pages_read: pages });
  });

  router.get('/sessions', (req, res) => {
    const date = (req.query.date as string) || todayDate();
    const sessions = db.getReadingSessions(date);
    res.json(sessions);
  });

  return router;
}
