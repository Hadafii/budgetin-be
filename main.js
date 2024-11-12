const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

const database = mysql.createConnection({
    host: "127.0.0.1",
    user: "dafiutom_admin",
    password: "BudgetinDB6623~;#m12,PZB{{/?&*8c5K",
    database: "dafiutom_BudgetinDB"
});

database.connect((err) => {
    if (err) throw err;
    console.log("Database connected");
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "hello.html"));
});
// Secret key untuk JWT
const JWT_SECRET = "1n1_KuNc1-T0K3N-MAM_APPLICATION_IPPL_AsoyGeboy"; // Gantilah dengan key yang aman

// Endpoint login yang menghasilkan token
app.post("/GatewayApi/v1/loginUser", (req, res) => {
    const { username, password } = req.body;
    const query = "SELECT * FROM users WHERE username = ? AND password = ?";
    database.query(query, [username, password], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else if (rows.length > 0) {
            const user = rows[0];
            // Pastikan untuk menggunakan `user.user_id` jika itu nama kolom ID-nya
            const token = jwt.sign({ id: user.user_id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
            res.json({ success: true, message: "Login successful", token });
        } else {
            res.json({ success: false, message: "Invalid username or password" });
        }
    });
});



// Middleware untuk memverifikasi token
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access denied" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification error:", err);
            return res.status(403).json({ message: "Invalid token" });
        }
        
        req.user = user;
        next();
    });
}



// Endpoint untuk mendapatkan data pengguna berdasarkan token
app.get("/GatewayApi/v1/users", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = "SELECT * FROM users WHERE user_id = ?"; 
    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else {
            res.json({ success: true, data: rows[0] });
        }
    });
});

app.get("/GatewayApi/v1/AccountData", authenticateToken, (req, res) => {
    const userId = req.user.id;


    const query = "SELECT account_name FROM accounts WHERE user_id = ?";
    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else if (rows.length > 0) {
            console.log("Account Name:", rows[0].account_name); 
            res.json({ success: true, account_name: rows[0].account_name });
        } else {
            console.log("Account not found for user ID:", userId);
            res.json({ success: false, message: "Account not found" });
        }
    });
});

// Check if username exists
app.get("/GatewayApi/v1/checkUsername", (req, res) => {
    const { username } = req.query;
    const query = "SELECT * FROM users WHERE username = ?";
    database.query(query, [username], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else if (rows.length > 0) {
            res.json({ success: false, message: "Username already taken" });
        } else {
            res.json({ success: true, message: "Username available" });
        }
    });
});

// Register new user
// Register new user
app.post("/GatewayApi/v1/registerUser", (req, res) => {
    const { username, password, email, account_name, birth_date, gender, role } = req.body;

    // Langkah 1: Cari occupation_id berdasarkan role (misalnya, "Student" atau "Worker")
    const queryOccupation = "SELECT occupation_id FROM occupations WHERE occupation_name = ?";
    database.query(queryOccupation, [role], (err, occupationResult) => {
        if (err) {
            console.error("Database error (occupations):", err);
            return res.status(500).json({ success: false, message: "Database error in occupations table" });
        }

        if (occupationResult.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid role specified" });
        }

        const occupation_id = occupationResult[0].occupation_id; // Dapatkan occupation_id

        // Langkah 2: Simpan ke tabel `users`
        const queryUsers = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
        database.query(queryUsers, [username, password, email], (err, userResult) => {
            if (err) {
                console.error("Database error (users):", err);
                return res.status(500).json({ success: false, message: "Database error in users table" });
            }

            const userId = userResult.insertId; // Dapatkan ID user yang baru dibuat

            // Langkah 3: Simpan ke tabel `accounts` dengan menggunakan `occupation_id`
            const queryAccounts = "INSERT INTO accounts (user_id, account_name, birth_date, gender, occupation_id) VALUES (?, ?, ?, ?, ?)";
            database.query(queryAccounts, [userId, account_name, birth_date, gender, occupation_id], (err, accountResult) => {
                if (err) {
                    console.error("Database error (accounts):", err);
                    return res.status(500).json({ success: false, message: "Database error in accounts table" });
                }

                // Setelah user terdaftar di kedua tabel, buat token
                const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: "1h" });
                
                // Kirim token sebagai respons
                res.json({ success: true, message: "User registered successfully", token });
            });
        });
    });
});

app.get("/GatewayApi/v1/allUsernames", (req, res) => {
    const query = "SELECT username FROM users";
    database.query(query, (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else {
            const usernames = rows.map(row => row.username);
            res.json({ success: true, usernames });
        }
    });
});

app.get("/GatewayApi/v1/getUserBalance", authenticateToken, (req, res) => {
    const userId = req.user.id; // Extract user ID from the JWT token

    const query = "SELECT balance FROM accounts WHERE user_id = ?";
    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else if (rows.length > 0) {
            res.json({ success: true, balance: rows[0].balance });
        } else {
            res.json({ success: false, message: "Account not found" });
        }
    });
});



app.listen(62542, () => {
    console.log("Server is running on port 3001");
});
