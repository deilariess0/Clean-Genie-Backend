const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// 🔒 SECURITY FIX: Allow Vercel (Admin), GitHub Pages (Customer), AND local development
app.use(cors({
    origin: [
        'https://booking-service-management-dashboard.vercel.app', // Admin Dashboard
        'https://delaries0.github.io', // Customer Booking Page (GitHub Pages)
        'http://localhost:5173', // Admin Local dev server
        'http://127.0.0.1:5173',
        /\.vercel\.app$/, // Allows ANY Vercel generated domain
        /\.github\.io$/   // Allows ANY GitHub Pages domain
    ],
    credentials: true
}));

// Use express.json instead of bodyParser.json (built-in)
app.use(express.json());

// ==========================================
// DATABASE CONNECTION (Render Friendly & Pooled)
// ==========================================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306, // <--- Reads 10769 from Render
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false 
});

// Test the connection pool
db.getConnection((err, connection) => {
    if (err) {
        console.error("Database connection failed, but continuing server without DB:", err.message);
    } else {
        console.log("Database connected!");
        connection.release(); // Release the connection back to the pool
    }
});

// 🔒 Initialize Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ==========================================
// ROOT ROUTE (REQUIRED FOR RENDER)
// ==========================================
// This prevents Render from seeing a 404 and killing the server
app.get('/', (req, res) => {
    res.send('Clean Genie Backend is running successfully!');
});

// ==========================================
// AUTH ROUTES
// ==========================================
// (All of your existing Auth routes remain exactly the same)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, full_name } = req.body;
    if (!email || !password || !full_name) return res.status(400).json({ error: 'All fields are required' });

    db.query('SELECT COUNT(*) as count FROM admins', async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        const adminCount = results[0].count;

        if (adminCount > 0) {
            return res.status(403).json({ error: 'Access Denied: Only the Super Admin can create accounts. Please contact the Super Admin.' });
        }

        db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length > 0) return res.status(409).json({ error: 'Email already registered' });

            const hashedPassword = await bcrypt.hash(password, 10);
            const sql = "INSERT INTO admins (email, password, full_name, role) VALUES (?, ?, ?, 'SUPER_ADMIN')";
            db.query(sql, [email, hashedPassword, full_name], (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                const token = jwt.sign({ id: result.insertId, email, full_name, role: 'SUPER_ADMIN' }, process.env.JWT_SECRET, { expiresIn: '1d' });
                res.status(201).json({ message: 'Admin registered successfully', token, admin: { id: result.insertId, email, full_name, role: 'SUPER_ADMIN' } });
            });
        });
    });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

        const admin = results[0];
        const passwordMatch = await bcrypt.compare(password, admin.password || '');
        if (!passwordMatch) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign({ id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token, admin: { id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role } });
    });
});

app.post('/api/auth/google', async (req, res) => {
    const { credential } = req.body;

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, sub: googleId } = payload;

        db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (results.length === 0) {
                const sql = "INSERT INTO admins (email, full_name, role, google_id) VALUES (?, ?, 'ADMIN', ?)";
                db.query(sql, [email, name, googleId], (err, result) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    const token = jwt.sign({ id: result.insertId, email, full_name: name, role: 'ADMIN' }, process.env.JWT_SECRET, { expiresIn: '1d' });
                    res.status(201).json({ token, admin: { id: result.insertId, email, full_name: name, role: 'ADMIN' } });
                });
            } else {
                const admin = results[0];
                const token = jwt.sign({ id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
                res.status(200).json({ token, admin: { id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role } });
            }
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(401).json({ error: 'Invalid Google token' });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const requireSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ error: 'Access Denied: Super Admin privileges required.' });
    }
    next();
};

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// ==========================================
// ADMIN MANAGEMENT ROUTES (SUPER ADMIN ONLY)
// ==========================================
// (All your existing Admin routes remain exactly the same)

app.get('/api/admins', authenticateToken, requireSuperAdmin, (req, res) => {
    const sql = "SELECT id, email, full_name, role, created_at FROM admins";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(200).json(results);
    });
});

app.post('/api/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { email, password, full_name, role } = req.body;
    if (!email || !password || !full_name) {
        return res.status(400).json({ error: 'Email, password, and full name required' });
    }

    db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length > 0) return res.status(409).json({ error: 'Admin with this email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const finalRole = role === 'SUPER_ADMIN' ? 'SUPER_ADMIN' : 'ADMIN';
        const sql = "INSERT INTO admins (email, password, full_name, role) VALUES (?, ?, ?, ?)";
        db.query(sql, [email, hashedPassword, full_name, finalRole], (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ message: 'Admin added successfully', id: result.insertId });
        });
    });
});

app.put('/api/admins/:id/role', authenticateToken, requireSuperAdmin, (req, res) => {
    const { role } = req.body;
    if (!['SUPER_ADMIN', 'ADMIN'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }
    const sql = "UPDATE admins SET role = ? WHERE id = ?";
    db.query(sql, [role, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
        res.json({ message: 'Role updated successfully' });
    });
});

app.delete('/api/admins/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    const sql = "DELETE FROM admins WHERE id = ?";
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
        res.json({ message: 'Admin deleted successfully' });
    });
});

// ==========================================
// BOOKING ROUTES (SECURED WITH AUTH)
// ==========================================

app.post('/api/bookings', (req, res) => {
    const {
        full_name, phone, email, service_address, service_type, area_size, 
        price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes
    } = req.body;

    if (!full_name || !phone || !email || !service_address || !service_type || !preferred_date) {
        return res.status(400).json({ success: false, message: "Missing required fields." });
    }

    const sql = `
        INSERT INTO bookings 
        (full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes || null];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error("Error saving booking:", err);
            return res.status(500).json({ success: false, message: "Database error", error: err.message });
        }
        res.status(201).json({ success: true, message: "Booking submitted successfully!", bookingId: result.insertId });
    });
});

// All these are protected by authenticateToken
app.get('/api/bookings', authenticateToken, (req, res) => {
    const sql = "SELECT id, full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, payment_status, payment_reference, booking_status, notes, created_at FROM bookings ORDER BY created_at DESC";
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching data" });
        res.status(200).json(result);
    });
});

app.get('/api/bookings/:id', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const sql = "SELECT * FROM bookings WHERE id = ?";
    db.query(sql, [bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching data" });
        if (result.length === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        res.status(200).json(result[0]);
    });
});

app.put('/api/bookings/:id/status', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const { booking_status } = req.body;
    const allowedStatuses = ['PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED'];
    if (!allowedStatuses.includes(booking_status)) {
        return res.status(400).json({ success: false, message: "Invalid booking status" });
    }
    const sql = "UPDATE bookings SET booking_status = ? WHERE id = ?";
    db.query(sql, [booking_status, bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        const selectSql = "SELECT * FROM bookings WHERE id = ?";
        db.query(selectSql, [bookingId], (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: "Error fetching updated booking" });
            res.status(200).json({ success: true, message: "Booking status updated successfully", booking: rows[0] });
        });
    });
});

app.put('/api/bookings/:id/payment', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const { payment_status } = req.body;
    const allowedStatuses = ['PENDING', 'PAID', 'REFUNDED', 'FAILED'];
    if (!allowedStatuses.includes(payment_status)) {
        return res.status(400).json({ success: false, message: "Invalid payment status" });
    }
    const sql = "UPDATE bookings SET payment_status = ? WHERE id = ?";
    db.query(sql, [payment_status, bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        const selectSql = "SELECT * FROM bookings WHERE id = ?";
        db.query(selectSql, [bookingId], (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: "Error fetching updated booking" });
            res.status(200).json({ success: true, message: "Payment status updated successfully", booking: rows[0] });
        });
    });
});

app.delete('/api/bookings/:id', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const sql = "DELETE FROM bookings WHERE id = ?";
    db.query(sql, [bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        res.status(200).json({ success: true, message: "Booking deleted successfully" });
    });
});

// Start the Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
