import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

const state = {
  profile: { name: 'عاصم إبراهيم', baseIncome: 30000, targetSavings: 8000 },
  transactions: [
    { id: 1, type: 'expense', amount: 6000, category: 'السكن', method: 'تحويل بنكي', desc: 'إيجار الشقة الشهري', date: new Date().toISOString().slice(0, 8) + '01' },
    { id: 2, type: 'expense', amount: 2450, category: 'الطعام والشراب', method: 'بطاقة بنكية', desc: 'خضار ومشتريات السوبرماركت', date: new Date(Date.now() - 86400000 * 3).toISOString().slice(0, 10) },
    { id: 3, type: 'expense', amount: 850, category: 'المواصلات', method: 'نقدًا', desc: 'تموين بنزين ومواصلات أوبر', date: new Date(Date.now() - 86400000 * 2).toISOString().slice(0, 10) }
  ],
  bills: [{ amount: 950, isPaid: false }, { amount: 750, isPaid: false }]
};

function summary() {
  const income = state.profile.baseIncome + state.transactions.filter(t => t.type === 'income').reduce((n, t) => n + Number(t.amount), 0);
  const expenses = state.transactions.filter(t => t.type === 'expense').reduce((n, t) => n + Number(t.amount), 0);
  const bills = state.bills.filter(b => !b.isPaid).reduce((n, b) => n + Number(b.amount), 0);
  const disposable = Math.max(income - expenses - bills - state.profile.targetSavings, 0);
  return { income, expenses, bills, disposable, cash: income - expenses, transactions: state.transactions.length };
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'smart-money-api', version: '1.0.0', timestamp: new Date().toISOString() }));
app.get('/api/summary', (_req, res) => res.json({ ok: true, data: summary() }));
app.get('/api/transactions', (_req, res) => res.json({ ok: true, data: state.transactions }));
app.post('/api/transactions', (req, res) => {
  const { type, amount, category, method, desc, date } = req.body || {};
  if (!['income', 'expense'].includes(type) || !Number.isFinite(Number(amount)) || Number(amount) <= 0 || !desc) {
    return res.status(400).json({ ok: false, error: 'بيانات المعاملة غير مكتملة' });
  }
  const transaction = { id: Date.now(), type, amount: Number(amount), category: category || 'أخرى', method: method || 'نقدًا', desc: String(desc).slice(0, 160), date: date || new Date().toISOString().slice(0, 10) };
  state.transactions.push(transaction);
  return res.status(201).json({ ok: true, data: transaction, summary: summary() });
});
app.delete('/api/transactions/:id', (req, res) => {
  const before = state.transactions.length;
  state.transactions = state.transactions.filter(t => String(t.id) !== String(req.params.id));
  if (state.transactions.length === before) return res.status(404).json({ ok: false, error: 'المعاملة غير موجودة' });
  return res.json({ ok: true, summary: summary() });
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(port, '0.0.0.0', () => console.log(`Smart Money AI listening on 0.0.0.0:${port}`));
