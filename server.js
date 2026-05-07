require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcrypt");
const jwt     = require("jsonwebtoken");
const mysql   = require("mysql2/promise");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// ─── Koneksi Database ───────────────────────────────────────────
const db = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port:     parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── Health check — Railway butuh endpoint yang response cepat ──
app.get("/", (req, res) => res.send("SIMPRO Backend Running"));
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ─── Middleware JWT ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Token tidak ada" });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token tidak valid" });
  }
}

// ─── Helpers ────────────────────────────────────────────────────
function hitungStatus(jumlah) {
  if (jumlah <= 0)  return "Habis";
  if (jumlah <= 20) return "Hampir Habis";
  return "Tersedia";
}

function bersihkanTanggal(tgl) {
  if (!tgl) return new Date().toISOString().split("T")[0];
  return String(tgl).split("T")[0];
}

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "Semua field harus diisi" });
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (username, email, password) VALUES (?,?,?)",
      [username, email, hash]
    );
    const [rows] = await db.query("SELECT * FROM users WHERE username=?", [username]);
    const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.status(201).json({ token });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY")
      return res.status(409).json({ error: "Username atau email sudah dipakai" });
    console.error("POST /auth/register error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await db.query("SELECT * FROM users WHERE username=?", [username]);
    if (!rows.length) return res.status(401).json({ error: "User tidak ditemukan" });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: "Password salah" });
    const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: "8h" });
    res.json({ token });
  } catch (err) {
    console.error("POST /auth/login error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/lupa-password", async (req, res) => {
  try {
    const { username } = req.body;
    const [rows] = await db.query(
      "SELECT id FROM users WHERE username=? OR email=?",
      [username, username]
    );
    if (!rows.length) return res.status(404).json({ error: "Akun tidak ditemukan" });
    res.json({ message: "Akun ditemukan. Hubungi admin untuk reset password." });
  } catch (err) {
    console.error("POST /auth/lupa-password error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ════════════════════════════════════════════════════════════════
// STOK PRODUKSI
// ════════════════════════════════════════════════════════════════

app.get("/api/stok", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM stok_produksi WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /api/stok error:", err.message);
    res.status(500).json({ error: "Gagal mengambil data stok" });
  }
});

app.post("/api/stok", authMiddleware, async (req, res) => {
  try {
    const { tanggal, produk_key, produk_nama, jumlah } = req.body;
    const tanggalBersih = bersihkanTanggal(tanggal);
    const jumlahInt = parseInt(jumlah, 10);
    const status = hitungStatus(jumlahInt);
    const [result] = await db.query(
      "INSERT INTO stok_produksi (tanggal, produk_key, produk_nama, jumlah, status, user_id) VALUES (?,?,?,?,?,?)",
      [tanggalBersih, produk_key, produk_nama, jumlahInt, status, req.user.id]
    );
    const [rows] = await db.query("SELECT * FROM stok_produksi WHERE id=?", [result.insertId]);
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("POST /api/stok error:", err.message);
    res.status(500).json({ error: "Gagal menambah stok" });
  }
});

app.put("/api/stok/:id", authMiddleware, async (req, res) => {
  try {
    const jumlahInt = parseInt(req.body.jumlah, 10);
    const status = hitungStatus(jumlahInt);
    await db.query(
      "UPDATE stok_produksi SET jumlah=?, status=? WHERE id=? AND user_id=?",
      [jumlahInt, status, req.params.id, req.user.id]
    );
    const [rows] = await db.query("SELECT * FROM stok_produksi WHERE id=?", [req.params.id]);
    res.json(rows[0]);
  } catch (err) {
    console.error("PUT /api/stok error:", err.message);
    res.status(500).json({ error: "Gagal update stok" });
  }
});

// ════════════════════════════════════════════════════════════════
// DISTRIBUSI
// ════════════════════════════════════════════════════════════════

app.get("/api/distribusi", authMiddleware, async (req, res) => {
  try {
    res.setHeader("Cache-Control", "no-store");
    const [rows] = await db.query(
      "SELECT * FROM distribusi WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /api/distribusi error:", err.message);
    res.status(500).json({ error: "Gagal mengambil distribusi" });
  }
});

app.post("/api/distribusi", authMiddleware, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const userId = req.user.id;
    const {
      tgl_distribusi, pelanggan, telp_pelanggan, no_kendaraan,
      telp_kondektur, lokasi, produk_key, tgl_produksi, kadaluarsa
    } = req.body;
    const jumlah = parseInt(req.body.jumlah, 10);
    const total  = parseInt(req.body.total,  10) || 0;

    const [stokRows] = await conn.query(
      "SELECT id, jumlah FROM stok_produksi WHERE produk_key=? AND jumlah>0 AND user_id=? ORDER BY tanggal ASC LIMIT 1 FOR UPDATE",
      [produk_key, userId]
    );
    if (!stokRows.length) throw new Error("Stok tidak ditemukan untuk produk ini");

    const stokTersedia = parseInt(stokRows[0].jumlah, 10);
    if (stokTersedia < jumlah)
      throw new Error(`Stok tidak cukup. Tersedia: ${stokTersedia}, diminta: ${jumlah}`);

    const stokBaru = stokTersedia - jumlah;
    await conn.query(
      "UPDATE stok_produksi SET jumlah=?, status=? WHERE id=?",
      [stokBaru, hitungStatus(stokBaru), stokRows[0].id]
    );

    const [result] = await conn.query(
      `INSERT INTO distribusi (tgl_distribusi, pelanggan, telp_pelanggan, no_kendaraan,
       telp_kondektur, lokasi, produk_key, tgl_produksi, jumlah, total, kadaluarsa, user_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        bersihkanTanggal(tgl_distribusi), pelanggan, telp_pelanggan, no_kendaraan,
        telp_kondektur, lokasi, produk_key, bersihkanTanggal(tgl_produksi),
        jumlah, total, bersihkanTanggal(kadaluarsa), userId
      ]
    );

    await conn.commit();
    const [rows] = await db.query("SELECT * FROM distribusi WHERE id=?", [result.insertId]);
    res.status(201).json(rows[0]);
  } catch (err) {
    await conn.rollback();
    console.error("POST /api/distribusi error:", err.message);
    res.status(400).json({ error: err.message || "Gagal tambah distribusi" });
  } finally {
    conn.release();
  }
});

app.put("/api/distribusi/:id", authMiddleware, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const userId = req.user.id;
    const distId = req.params.id;
    const { pelanggan, tgl_distribusi, telp_pelanggan, no_kendaraan, telp_kondektur, lokasi } = req.body;
    const jumlah = parseInt(req.body.jumlah, 10);
    const total  = parseInt(req.body.total,  10) || 0;

    const [lama] = await conn.query(
      "SELECT * FROM distribusi WHERE id=? AND user_id=?",
      [distId, userId]
    );
    if (!lama.length) throw new Error("Distribusi tidak ditemukan");

    const selisih = jumlah - parseInt(lama[0].jumlah, 10);
    if (selisih !== 0) {
      const [stokRows] = await conn.query(
        "SELECT id, jumlah FROM stok_produksi WHERE produk_key=? AND jumlah>0 AND user_id=? ORDER BY tanggal ASC LIMIT 1 FOR UPDATE",
        [lama[0].produk_key, userId]
      );
      if (!stokRows.length) throw new Error("Data stok tidak ditemukan");
      const stokTersedia = parseInt(stokRows[0].jumlah, 10);
      if (selisih > 0 && stokTersedia < selisih)
        throw new Error("Stok tidak cukup untuk penambahan");
      const stokBaru = stokTersedia - selisih;
      await conn.query(
        "UPDATE stok_produksi SET jumlah=?, status=? WHERE id=?",
        [stokBaru, hitungStatus(stokBaru), stokRows[0].id]
      );
    }

    await conn.query(
      `UPDATE distribusi SET tgl_distribusi=?, pelanggan=?, telp_pelanggan=?,
       no_kendaraan=?, telp_kondektur=?, lokasi=?, jumlah=?, total=? WHERE id=? AND user_id=?`,
      [bersihkanTanggal(tgl_distribusi), pelanggan, telp_pelanggan,
       no_kendaraan, telp_kondektur, lokasi, jumlah, total, distId, userId]
    );

    await conn.commit();
    const [rows] = await db.query("SELECT * FROM distribusi WHERE id=?", [distId]);
    res.json(rows[0]);
  } catch (err) {
    await conn.rollback();
    console.error("PUT /api/distribusi error:", err.message);
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

app.delete("/api/distribusi/:id", authMiddleware, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const userId = req.user.id;

    const [rows] = await conn.query(
      "SELECT * FROM distribusi WHERE id=? AND user_id=?",
      [req.params.id, userId]
    );
    if (!rows.length) throw new Error("Distribusi tidak ditemukan");

    const d = rows[0];
    const jumlahKembali = parseInt(d.jumlah, 10);

    const [stokRows] = await conn.query(
      "SELECT id, jumlah FROM stok_produksi WHERE produk_key=? AND user_id=? ORDER BY tanggal ASC LIMIT 1",
      [d.produk_key, userId]
    );
    if (stokRows.length) {
      const stokBaru = parseInt(stokRows[0].jumlah, 10) + jumlahKembali;
      await conn.query(
        "UPDATE stok_produksi SET jumlah=?, status=? WHERE id=?",
        [stokBaru, hitungStatus(stokBaru), stokRows[0].id]
      );
    }

    await conn.query("DELETE FROM distribusi WHERE id=? AND user_id=?", [req.params.id, userId]);
    await conn.commit();
    res.json({ message: "Distribusi berhasil dihapus" });
  } catch (err) {
    await conn.rollback();
    console.error("DELETE /api/distribusi error:", err.message);
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

app.put("/api/distribusi/:id/status", authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    await db.query(
      "UPDATE distribusi SET status=? WHERE id=? AND user_id=?",
      [status, req.params.id, req.user.id]
    );
    const [rows] = await db.query("SELECT * FROM distribusi WHERE id=?", [req.params.id]);
    res.json(rows[0]);
  } catch (err) {
    console.error("PUT /api/distribusi/status error:", err.message);
    res.status(500).json({ error: "Gagal update status" });
  }
});

// ════════════════════════════════════════════════════════════════
// KEUNTUNGAN
// ════════════════════════════════════════════════════════════════

app.get("/api/keuntungan", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
        DATE_FORMAT(tgl_distribusi, '%Y-%m') AS bulan,
        SUM(total) AS total_keuntungan,
        SUM(jumlah) AS jumlah_transaksi
      FROM distribusi
      WHERE status = 'Sudah Terkirim' AND user_id = ?
      GROUP BY bulan
      ORDER BY bulan DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (err) {
    console.error("GET /api/keuntungan error:", err.message);
    res.status(500).json({ error: "Gagal ambil data keuntungan" });
  }
});

// ════════════════════════════════════════════════════════════════
// START SERVER
// ════════════════════════════════════════════════════════════════

// Gunakan PORT dari environment — Railway otomatis set ini
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SIMPRO API berjalan di port ${PORT}`);
});
