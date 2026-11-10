require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const isProduction = process.env.NODE_ENV === "production";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({ extended: false, limit: "30kb" }));

// Диагностика: этот адрес должен открываться на том же домене, что и сайт.
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (error) {
    console.error("Health check database error:", error);
    res.status(503).json({ ok: false, database: "disconnected", error: "База данных недоступна. Проверь DATABASE_URL и настройки PostgreSQL на хостинге." });
  }
});

pool.on("error", (error) => console.error("PostgreSQL pool error:", error));

app.use(session({
  store: new PgSession({ pool, createTableIfMissing: true }),
  name: "friendship.sid",
  secret: process.env.SESSION_SECRET || "dev-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const questions = [
  "Кто ты для этого человека?",
  "Какой мой любимый цвет?",
  "Чем я больше всего люблю заниматься в свободное время?",
  "Какую музыку я чаще всего слушаю?",
  "Как я предпочитаю проводить выходные?",
  "Что меня быстрее всего рассмешит?",
  "Что для меня важнее всего в дружбе?",
  "Какой подарок мне понравится больше?",
  "Как я обычно реагирую на проблему?",
  "Что я выберу: прогулку или домашний отдых?",
  "Насколько хорошо ты думаешь, что знаешь меня?"
];
const choices = [
  ["Сестра", "Брат", "Подруга", "Друг", "Девушка", "Парень"],
  ["Чёрный", "Белый", "Синий", "Красный"],
  ["Играть", "Гулять", "Смотреть фильмы", "Слушать музыку"],
  ["Поп", "Рэп", "Рок", "Разную"],
  ["Дома", "На улице", "С друзьями", "За любимым занятием"],
  ["Шутка", "Мем", "Неожиданная ситуация", "Всё вместе"],
  ["Честность", "Юмор", "Поддержка", "Доверие"],
  ["Техника", "Одежда", "Подарок своими руками", "Впечатление"],
  ["Сначала думаю", "Сразу действую", "Советуюсь", "Шучу"],
  ["Прогулку", "Домашний отдых", "Оба варианта", "Зависит от настроения"],
  ["Очень хорошо", "Хорошо", "Пока не очень", "Проверим!"]
];

async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(24) UNIQUE NOT NULL,
            email VARCHAR(254) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            notification_email VARCHAR(254),
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS answer_keys (
            user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            answers JSONB NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id BIGSERIAL PRIMARY KEY,
            owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            sender_username VARCHAR(24) NOT NULL,
            answers JSONB NOT NULL,
            score INTEGER NOT NULL,
            relationship VARCHAR(30),
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        ALTER TABLE submissions
        ADD COLUMN IF NOT EXISTS relationship VARCHAR(30);
    `);
}

const authLimiter = rateLimit({ windowMs: 15 *  60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Сначала войди в аккаунт." });
  next();
}
function validEmail(email) {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validUsername(username) {
  return typeof username === "string" && /^[a-zA-Z0-9_]{3,24}$/.test(username);
}
function getMailer() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

app.get("/api/me", async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const { rows } = await pool.query(
    "SELECT id, username, email, notification_email FROM users WHERE id=$1",
    [req.session.userId]
  );
  if (!rows[0]) { req.session.destroy(() => {}); return res.json({ user: null }); }
  res.json({ user: rows[0] });
});

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: "Имя аккаунта: 3–24 символа, только латинские буквы, цифры и _." });
  if (!validEmail(email)) return res.status(400).json({ error: "Укажи корректный email." });
  if (typeof password !== "string" || password.length < 8 || password.length > 100)
    return res.status(400).json({ error: "Пароль должен содержать от 8 до 100 символов." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id,username,email,notification_email",
      [username.toLowerCase(), email.toLowerCase(), hash]
    );
    req.session.userId = rows[0].id;
    res.json({ user: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Такое имя аккаунта или email уже заняты." });
    console.error(e); res.status(500).json({ error: "Не удалось создать аккаунт." });
  }
});

app.post("/api/login", async (req, res) => {
  const { login, password } = req.body || {};
  if (typeof login !== "string" || typeof password !== "string") return res.status(400).json({ error: "Заполни оба поля." });
  try {
    const { rows } = await pool.query(
      "SELECT id,username,email,notification_email,password_hash FROM users WHERE username=$1 OR email=$1",
      [login.toLowerCase()]
    );
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash)))
      return res.status(401).json({ error: "Неверный логин или пароль." });
    req.session.userId = rows[0].id;
    delete rows[0].password_hash;
    res.json({ user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка входа." }); }
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.put("/api/settings", requireAuth, async (req, res) => {
  const email = (req.body || {}).notificationEmail;
  if (email && !validEmail(email)) return res.status(400).json({ error: "Проверь адрес email." });
  try {
    await pool.query("UPDATE users SET notification_email=$1 WHERE id=$2", [email || null, req.session.userId]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось сохранить настройки." }); }
});

app.get("/api/questions", requireAuth, (req, res) => res.json({ questions, choices }));

app.put("/api/answer-key", requireAuth, async (req, res) => {
  const answers = (req.body || {}).answers;
  if (!Array.isArray(answers) || answers.length !== questions.length ||
      answers.some((v, i) => !Number.isInteger(v) || v < 0 || v >= choices[i].length))
    return res.status(400).json({ error: "Выбери ответ на каждый вопрос." });
  try {
    await pool.query(
      `INSERT INTO answer_keys(user_id,answers) VALUES($1,$2::jsonb)
       ON CONFLICT(user_id) DO UPDATE SET answers=EXCLUDED.answers,updated_at=NOW()`,
      [req.session.userId, JSON.stringify(answers)]
    );
    res.json({ ok: true, link: `${process.env.BASE_URL || "http://localhost:3000"}/?friend=${encodeURIComponent((await pool.query("SELECT username FROM users WHERE id=$1",[req.session.userId])).rows[0].username)}` });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось сохранить ответы." }); }
});

app.get("/api/test/:username", requireAuth, async (req, res) => {
  const username = String(req.params.username).toLowerCase();
  const { rows } = await pool.query("SELECT id,username FROM users WHERE username=$1", [username]);
  if (!rows[0]) return res.status(404).json({ error: "Аккаунт не найден." });
  const key = await pool.query("SELECT user_id FROM answer_keys WHERE user_id=$1", [rows[0].id]);
  if (!key.rows[0]) return res.status(404).json({ error: "Этот пользователь ещё не подготовил тест." });
  if (String(rows[0].id) === String(req.session.userId)) return res.status(400).json({ error: "Нельзя пройти собственный тест." });
  res.json({ username: rows[0].username, questions, choices });
});

app.post("/api/test/:username/submit", requireAuth, async (req, res) => {
  const username = String(req.params.username).toLowerCase();
  const answers = (req.body || {}).answers;
  if (!Array.isArray(answers) || answers.length !== questions.length ||
      answers.some((v, i) => !Number.isInteger(v) || v < 0 || v >= choices[i].length))
    return res.status(400).json({ error: "Ответь на все вопросы." });
  try {
    const ownerResult = await pool.query(
      `SELECT u.id,u.username,u.email,u.notification_email,k.answers
       FROM users u JOIN answer_keys k ON k.user_id=u.id WHERE u.username=$1`, [username]
    );
    const owner = ownerResult.rows[0];
    if (!owner) return res.status(404).json({ error: "Тест не найден." });
    if (String(owner.id) === String(req.session.userId)) return res.status(400).json({ error: "Нельзя пройти собственный тест." });
    const me = (await pool.query("SELECT username FROM users WHERE id=$1", [req.session.userId])).rows[0];
    const correct = owner.answers;
    const score = Math.round(answers.reduce((sum, value, i) => sum + (value === correct[i] ? 1 : 0), 0) / questions.length * 100);
    await pool.query(
      "INSERT INTO submissions(owner_id,sender_id,sender_username,answers,score) VALUES($1,$2,$3,$4::jsonb,$5)",
      [owner.id, req.session.userId, me.username, JSON.stringify(answers), score]
    );

    const recipient = owner.notification_email || process.env.OWNER_EMAIL || owner.email;
    const mailer = getMailer();
    let emailSent = false;
    if (mailer && recipient) {
      const answerLines = questions.map((q, i) => `${i + 1}. ${q}\nОтвет: ${choices[i][answers[i]]}`).join("\n\n");
      try {
        await mailer.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: recipient,
          subject: `Новый результат теста на дружбу от ${me.username}`,
          text: `Пользователь ${me.username} прошёл твой тест.\nРезультат: ${score}%\n\n${answerLines}`
        });
        emailSent = true;
      } catch (mailError) { console.error("Email error:", mailError); }
    }
    res.json({ score, owner: owner.username, emailSent });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось отправить ответы." }); }
});

app.get("/api/submissions", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id,sender_username,answers,score,created_at FROM submissions WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 100",
      [req.session.userId]
    );
    res.json({ submissions: rows, questions, choices });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось загрузить результаты." }); }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const port = Number(process.env.PORT || 3000);
if (!process.env.DATABASE_URL) {
  console.error("ОШИБКА: не задан DATABASE_URL. Добавь строку подключения PostgreSQL в .env или переменные окружения хостинга.");
  process.exit(1);
}
initDb()
  .then(() => app.listen(port, "0.0.0.0", () => console.log(`Сайт запущен на порту ${port}. Проверка: /api/health`)))
  .catch(err => {
    console.error("Не удалось подключиться к PostgreSQL. Проверь DATABASE_URL, доступность базы и PGSSL.", err);
    process.exit(1);
  });
