const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer"); 
const validator = require("validator");
const bcrypt = require("bcrypt");
const util = require("util");

//definiiin API
const app = express();
app.use(cors());
app.use(express.json());

//Connect to server
const database = mysql.createConnection({
    host: "127.0.0.1",
    user: "dafiutom_admin",
    password: "BudgetinDB6623~;#m12,PZB{{/?&*8c5K",
    database: "dafiutom_BudgetinDB"
});

const query = util.promisify(database.query).bind(database);
//connect attempt
database.connect((err) => {
    if (err) {
        console.error("error connecting:", err);
    }
    console.log("Database connected");
});

//Page Landing
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "hello.html"));
});

//Transporter Email
const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: "budgetinmailer@gmail.com", 
        pass: "amoy bbws ltub ynrv"   
    },
    // debug: true, // Menyalakan debugging
    // logger: true  // Menyalakan logging
});

// Secret key untuk JWT
const JWT_SECRET = "1n1_KuNc1-T0K3N-MAM_APPLICATION_IPPL_AsoyGeboy"; 


// Endpoint login yang menghasilkan token
app.post("/GatewayApi/v1/loginUser", async (req, res) => {
    const { username, password } = req.body;
    console.log("Login request received:", req.body);

    if (!username || !password) {
        console.log("Invalid request:", req.body);
        return res.status(400).json({ success: false, message: "Username and password are required." });
    }

    try {
        const rows = await query("SELECT * FROM users WHERE username = ?", [username]);
        console.log("Query result:", rows);

        if (rows.length === 0) {
            console.log("No user found with username:", username);
            return res.status(400).json({ success: false, message: "Invalid username or password." });
        }

        const user = rows[0];
        console.log("User data from database:", user);

        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log("Password validation result:", isPasswordValid);

        if (!isPasswordValid) {
            return res.status(400).json({ success: false, message: "Invalid username or password." });
        }

        const token = jwt.sign(
            { id: user.user_id, username: user.username },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log("Generated token:", token);
        res.json({ success: true, message: "Login successful", token });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
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

// Middleware untuk memeriksa validitas token
app.post("/GatewayApi/v1/checkToken", authenticateToken, (req, res) => {
    res.json({ success: true, message: "Token is valid" });
});


// Endpoint untuk memperbarui token JWT
app.post("/GatewayApi/v1/refreshToken", authenticateToken, (req, res) => {
    const userId = req.user.id; // Dapatkan user ID dari token yang ada

    // Buat token baru
    const newToken = jwt.sign(
        { id: userId, username: req.user.username },
        JWT_SECRET,
        { expiresIn: "1h" } // Durasi token baru
    );

    res.json({
        success: true,
        message: "Token refreshed successfully",
        token: newToken, // Kirim token baru ke frontend
    });
});



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

//Endpoint untuk mendapatkan Account name doang (API LAMA: /GatewayApi/v1/AccountData)
app.get("/GatewayApi/v1/AccountName", authenticateToken, (req, res) => {
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

//Endpoint signin yang cek if username exists
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

//Endpoiint Verifikasi Email
app.post("/GatewayApi/v1/registerUser", async (req, res) => {
    const { username, password, email, account_name, birth_date, gender, role } = req.body;

    // Validasi input
    if (!username || !password || !email || !account_name || !birth_date || !gender || !role) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }

    if (password.length < 8) {
        return res.status(400).json({ success: false, message: "Password must be at least 8 characters long." });
    }

    try {
        // Periksa apakah email sudah digunakan
        const existingUser = await query("SELECT * FROM users WHERE email = ?", [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already in use." });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate OTP
        const expireAt = new Date(Date.now() + 15 * 60 * 1000); // 15 menit dari sekarang

        const sqlQuery = `
            INSERT INTO temp_registrations (username, password, email, account_name, birth_date, gender, role, otp_code, expire_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        await query(sqlQuery, [username, hashedPassword, email, account_name, birth_date, gender, role, otp, expireAt]);

        // Kirim OTP ke email pengguna
        const mailOptions = {
            from: "no-reply@dafiutomo.com",
            to: email,
            subject: "Verify Your Email",
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.5;">
                    <h2 style="color: #333;">Verify Your Email</h2>
                    <p>Hello, ${account_name},</p>
                    <p>Thank you for registering. Please use the OTP code below to verify your email:</p>
                    <div style="text-align: center; margin: 20px 0;">
                        <span style="font-size: 24px; font-weight: bold; color: #15B7B9;">${otp}</span>
                    </div>
                    <p><strong>Note:</strong> This OTP will expire in 15 minutes. Do not share it with anyone.</p>
                    <p>If you did not request this, please ignore this email.</p>
                    <p>Best regards,<br>Budgetin Team</p>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error("Failed to send email:", error);
                return res.status(500).json({ success: false, message: "Failed to send verification email." });
            }

            res.json({ success: true, message: "OTP sent to email. Please verify your email within 15 minutes." });
        });
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, message: "Database error" });
    }
});



//cek emailnya udah ada apa belom
// Endpoint untuk memeriksa apakah email tersedia
app.get("/GatewayApi/v1/checkEmail", async (req, res) => {
    const { email } = req.query;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        const rows = await query("SELECT * FROM users WHERE email = ?", [email]);

        if (rows.length > 0) {
            return res.json({ success: false, message: "Email already in use." });
        } else {
            return res.json({ success: true, message: "Email is available." });
        }
    } catch (err) {
        console.error("Database error:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});



app.post("/GatewayApi/v1/resendOTP", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }

    const query = "SELECT * FROM temp_registrations WHERE email = ?";
    database.query(query, [email], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found in temporary registrations." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate OTP baru
        const expireAt = new Date(Date.now() + 15 * 60 * 1000); // 15 menit dari sekarang

        const queryUpdate = "UPDATE temp_registrations SET otp_code = ?, expire_at = ? WHERE email = ?";
        database.query(queryUpdate, [otp, expireAt, email], (err) => {
            if (err) {
                console.error("Database error during OTP update:", err);
                return res.status(500).json({ success: false, message: "Failed to update OTP and expiration time." });
            }

            // Kirim OTP baru ke email
            const mailOptions = {
                from: "no-reply@dafiutomo.com",
                to: email,
                subject: "Resend OTP",
                html: `
                    <div style="font-family: Arial, sans-serif; line-height: 1.5;">
                        <h2 style="color: #333;">Verify Your Email</h2>
                        <p>Hello,</p>
                        <p>We have received your request to resend the OTP for email verification. Use the code below to verify your email:</p>
                        <div style="text-align: center; margin: 20px 0;">
                            <span style="font-size: 24px; font-weight: bold; color: #15B7B9;">${otp}</span>
                        </div>
                        <p><strong>Note:</strong> This OTP will expire in 15 minutes. Do not share it with anyone for security purposes.</p>
                        <p>If you did not request this, please ignore this email.</p>
                        <p>Best regards,<br>Budgetin Team</p>
                    </div>
                `,
                text: `
                    Hello,

                    We have received your request to resend the OTP for email verification. Use the code below to verify your email:
                    
                    OTP: ${otp}

                    Note: This OTP will expire in 15 minutes. Do not share it with anyone for security purposes.

                    Best regards,
                    Budgetin Team
                `,
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    console.error("Failed to send email:", error);
                    return res.status(500).json({ success: false, message: "Failed to resend OTP." });
                }

                res.json({
                    success: true,
                    message: "OTP has been resent to your email. Please verify your email within 15 minutes.",
                });
            });
        });
    });
});



app.post("/GatewayApi/v1/verifyEmail", (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }

    database.beginTransaction((err) => {
        if (err) {
            console.error("Transaction start error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        // Step 1: Validate OTP
        const otpQuery = `
            SELECT * FROM temp_registrations 
            WHERE email = ? AND otp_code = ? AND expire_at > NOW()
        `;
        database.query(otpQuery, [email, otp], (otpErr, otpRows) => {
            if (otpErr) {
                console.error("OTP validation error:", otpErr);
                return database.rollback(() => {
                    res.status(500).json({ success: false, message: "Internal Server Error" });
                });
            }

            if (otpRows.length === 0) {
                return database.rollback(() => {
                    res.status(400).json({ success: false, message: "Invalid or expired OTP." });
                });
            }

            const { username, password, account_name, birth_date, gender, role } = otpRows[0];

            // Step 2: Map role to occupation_id
            const roleQuery = "SELECT occupation_id FROM occupations WHERE occupation_name = ?";
            database.query(roleQuery, [role], (roleErr, roleRows) => {
                if (roleErr || roleRows.length === 0) {
                    console.error("Role mapping error:", roleErr);
                    return database.rollback(() => {
                        res.status(500).json({ success: false, message: "Internal Server Error" });
                    });
                }

                const occupation_id = roleRows[0].occupation_id;

                // Step 3: Insert user into `users`
                const userQuery = `
                    INSERT INTO users (username, password, email, is_verified, is_hashed) 
                    VALUES (?, ?, ?, TRUE, TRUE)
                `;
                database.query(userQuery, [username, password, email], (userErr, userResult) => {
                    if (userErr) {
                        console.error("User creation error:", userErr);
                        return database.rollback(() => {
                            res.status(500).json({ success: false, message: "Internal Server Error" });
                        });
                    }

                    const userId = userResult.insertId;

                    // Step 4: Insert account into `accounts`
                    const accountQuery = `
                        INSERT INTO accounts (user_id, account_name, birth_date, gender, occupation_id)
                        VALUES (?, ?, ?, ?, ?)
                    `;
                    database.query(accountQuery, [userId, account_name, birth_date, gender, occupation_id], (accountErr) => {
                        if (accountErr) {
                            console.error("Account creation error:", accountErr);
                            return database.rollback(() => {
                                res.status(500).json({ success: false, message: "Internal Server Error" });
                            });
                        }

                        // Step 5: Add welcome notification
                        const welcomeMessage = "Selamat datang di Budgetin! Nikmati fitur kami untuk mengelola keuangan Anda.";
                        const notificationContext = "welcome-message";
                        const notificationQuery = `
                            INSERT INTO notifications (user_id, message, created_at, is_read, notification_context)
                            SELECT ?, ?, NOW(), 0, ?
                            WHERE NOT EXISTS (
                                SELECT 1 FROM notifications WHERE user_id = ? AND notification_context = ?
                            )
                        `;
                        database.query(notificationQuery, [
                            userId, welcomeMessage, notificationContext, userId, notificationContext
                        ], (notificationErr) => {
                            if (notificationErr) {
                                console.error("Notification creation error:", notificationErr);
                                return database.rollback(() => {
                                    res.status(500).json({ success: false, message: "Internal Server Error" });
                                });
                            }

                            // Step 6: Delete from `temp_registrations`
                            const deleteTempQuery = "DELETE FROM temp_registrations WHERE email = ?";
                            database.query(deleteTempQuery, [email], (deleteErr) => {
                                if (deleteErr) {
                                    console.error("Temp registrations delete error:", deleteErr);
                                    return database.rollback(() => {
                                        res.status(500).json({ success: false, message: "Internal Server Error" });
                                    });
                                }

                                // Commit the transaction
                                database.commit((commitErr) => {
                                    if (commitErr) {
                                        console.error("Transaction commit error:", commitErr);
                                        return database.rollback(() => {
                                            res.status(500).json({ success: false, message: "Internal Server Error" });
                                        });
                                    }

                                    // Generate JWT token
                                    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: "1h" });

                                    res.json({
                                        success: true,
                                        message: "Email verified and account created successfully",
                                        token, // Send token to the frontend
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});



//ENDPOINT FORGOT PASSWORD ADA 3

// Endpoint Forgot Password
app.post("/GatewayApi/v1/forgotPassword", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    const query = "SELECT * FROM users WHERE email = ?";
    database.query(query, [email], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found." });
        }

        const token = crypto.randomBytes(32).toString("hex"); // Generate token
        const resetLink = `https://budgetin.dafiutomo.com/reset-password?token=${token}`;
        const queryToken = `
            INSERT INTO password_resets (email, token, expires_at)
            VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE))
        `;

        database.query(queryToken, [email, token], (err) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: "Failed to store reset token." });
            }

            // Send email with the reset link
            const mailOptions = {
                from: "no-reply@dafiutomo.com",
                to: email,
                subject: "Reset Your Password",
                html: `
                    <div style="font-family: Arial, sans-serif; background-color: 'none'; padding: 20px; line-height: 1.6; color: #000000;">
                        <table align="center" width="100%" style="max-width: 600px; background-color: #ffffff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
                            <thead>
                                <tr>
                                    <td style="background-color: #15B7B9; padding: 20px; text-align: center; color: #ffffff; font-size: 24px; font-weight: bold;">
                                        Reset Your Password
                                    </td>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td style="padding: 20px;">
                                        <p>Hello,</p>
                                        <p>You have requested to reset your password. Click the button below to reset it:</p>
                                        <div style="text-align: center; margin: 20px 0;">
                                            <a href="${resetLink}" 
                                            style="display: inline-block; padding: 12px 20px; font-size: 16px; color: #ffffff; background-color: #15B7B9; border-radius: 5px; text-decoration: none;">
                                            Reset Password
                                            </a>
                                        </div>
                                        <p style="margin-top: 20px;">
                                            <strong>Note:</strong> This link will expire in 15 minutes. If you did not request this, please ignore this email.
                                        </p>
                                    </td>
                                </tr>
                            </tbody>
                            <tfoot>
                                <tr>
                                    <td style="background-color: #f4f4f4; text-align: center; padding: 10px; font-size: 12px; color: #777;">
                                        © 2024 Budgetin. All rights reserved.
                                    </td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                `
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    console.error("Failed to send email:", error);
                    return res.status(500).json({ success: false, message: "Failed to send reset email." });
                }

                res.json({ success: true, message: "Reset password link sent to your email." });
            });
        });
    });
});

// Endpoint Verify Reset Token
app.post("/GatewayApi/v1/verifyResetToken", (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ success: false, message: "Token is required." });
    }

    const query = "SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()";
    database.query(query, [token], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid or expired token." });
        }

        res.json({ success: true, message: "Token is valid.", email: rows[0].email });
    });
});

// Endpoint Reset Password
app.post("/GatewayApi/v1/resetPassword", async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ success: false, message: "Token and new password are required." });
    }

    try {
        const rows = await query("SELECT * FROM password_resets WHERE token = ? AND expires_at > NOW()", [token]);

        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid or expired token." });
        }

        const email = rows[0].email;

        // Hash password baru
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password di tabel `users`
        await query("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, email]);

        // Hapus token dari tabel `password_resets`
        await query("DELETE FROM password_resets WHERE token = ?", [token]);

        res.json({ success: true, message: "Password has been reset successfully." });
    } catch (error) {
        console.error("Error during password reset:", error);
        res.status(500).json({ success: false, message: "Internal server error." });
    }
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

//Endpoint buat ngambil data balances nya user
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

//Endpoint untuk /Profile buat nampilin semua data account yg dipake
app.get("/GatewayApi/v1/getUserData", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = "SELECT * FROM users JOIN accounts ON users.user_id = accounts.user_id WHERE users.user_id = ?";

    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length > 0) {
            res.json({ success: true, data: rows[0] });
        } else {
            res.status(404).json({ success: false, message: "User or account not found" });
        }
    });
});

//Endpoint update user data information aja, (account name, email, gender, phone, bio)
app.put("/GatewayApi/v1/updateUserInformation", authenticateToken, (req, res) => {
    const { account_name, gender, phone_number, bio, email } = req.body;
    const userId = req.user.id;

    const queryUsers = `UPDATE users SET email = ? WHERE user_id = ?`;
    const queryAccounts = `UPDATE accounts SET account_name = ?, gender = ?, phone_number = ?, bio = ? WHERE user_id = ?`;

    database.query(queryUsers, [email, userId], (err, result) => {
        if (err) {
            console.error("Database error in users table:", err);
            return res.status(500).json({ success: false, message: "Database error in users table" });
        }

        database.query(queryAccounts, [account_name, gender, phone_number, bio, userId], (err, result) => {
            if (err) {
                console.error("Database error in accounts table:", err);
                return res.status(500).json({ success: false, message: "Database error in accounts table" });
            }

            res.json({ success: true, message: "User information updated successfully" });
        });
    });
});

//Endpoint ngambil data password user
app.post("/GatewayApi/v1/verifyUserPassword", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ success: false, message: "Password is required." });
    }

    const query = "SELECT password FROM users WHERE user_id = ?";
    database.query(query, [userId], async (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        if (rows.length > 0) {
            const savedPassword = rows[0].password;

            try {
                const isPasswordValid = await bcrypt.compare(password, savedPassword);
                if (isPasswordValid) {
                    return res.json({ success: true, message: "Password verified successfully" });
                } else {
                    return res.status(401).json({ success: false, message: "Incorrect password" });
                }
            } catch (error) {
                console.error("Error comparing passwords:", error);
                return res.status(500).json({ success: false, message: "Internal server error." });
            }
        } else {
            return res.status(404).json({ success: false, message: "User not found." });
        }
    });
});




//Endpoint update password
app.put("/GatewayApi/v1/updateUserPassword", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({
            success: false,
            message: "Password must be at least 6 characters long.",
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10); // Hash new password
        const query = "UPDATE users SET password = ? WHERE user_id = ?";
        database.query(query, [hashedPassword, userId], (err, result) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: "Database error" });
            }
            res.json({ success: true, message: "Password updated successfully." });
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.put("/GatewayApi/v1/updateUserOccupation", authenticateToken, (req, res) => {
    const userId = req.user.id; // Mengambil user ID dari token
    const { occupation_id } = req.body; // Mengambil occupation_id baru dari body request

    const query = "UPDATE accounts SET occupation_id = ? WHERE user_id = ?";
    database.query(query, [occupation_id, userId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }
        
        if (result.affectedRows > 0) {
            res.json({ success: true, message: "Occupation updated successfully" });
        } else {
            res.status(404).json({ success: false, message: "Account not found" });
        }
    });
});

//Endpoint untuk card SisaBudget yg ngambil semua data transaksi
app.get("/GatewayApi/v1/getBudgetStatus", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM' for the current month

    console.log("User ID:", userId);
    console.log("Current Month:", currentMonth);

    // Step 1: Retrieve budget_id and total_budget for the current month
    const queryMonthlyBudget = `
        SELECT budget_id, total_budget 
        FROM monthlybudget 
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?) 
        AND month = ?
    `;
    
    database.query(queryMonthlyBudget, [userId, currentMonth], (err, rows) => {
        if (err) {
            console.error("Error fetching monthly budget:", err);
            return res.status(500).json({ success: false, message: "Error fetching monthly budget" });
        }

        if (rows.length === 0) {
            console.warn("No budget found for the current month.");
            return res.status(200).json({ success: true, data: [], message: "No budget found for the current month" });
        }

        const { budget_id, total_budget } = rows[0];
        console.log("Budget ID:", budget_id, "Total Budget:", total_budget);

        // Step 2: Retrieve budget details for Food and Beverage (category_id = 1), Shopping (category_id = 2)
        const queryBudgetDetails = `
            SELECT bd.category_id, bd.category_budget, bd.category_type, sc.category_name
            FROM budgetdetails bd
            JOIN spendingcategories sc ON bd.category_id = sc.category_id
            WHERE bd.budget_id = ? AND bd.category_id IN (1, 2)
        `;
        
        database.query(queryBudgetDetails, [budget_id], (err, budgetRows) => {
            if (err) {
                console.error("Error fetching budget details:", err);
                return res.status(500).json({ success: false, message: "Error fetching budget details" });
            }

            console.log("Budget Details:", budgetRows);

            // Step 3: Retrieve the "Others" categories (all category_id except 1 and 2)
            const queryOtherCategories = `
                SELECT category_id, category_budget 
                FROM budgetdetails 
                WHERE budget_id = ? AND category_id NOT IN (1, 2)
            `;
            
            database.query(queryOtherCategories, [budget_id], (err, otherCategoriesRows) => {
                if (err) {
                    console.error("Error fetching 'Other' categories:", err);
                    return res.status(500).json({ success: false, message: "Error fetching 'Other' categories" });
                }

                const otherCategoryIds = otherCategoriesRows.map(row => row.category_id);
                const totalOtherBudget = otherCategoriesRows.reduce((sum, row) => sum + row.category_budget, 0);
                console.log("Other Category IDs:", otherCategoryIds);
                console.log("Total Other Budget:", totalOtherBudget);

                // Step 4: Retrieve spending data for Food and Beverage, Shopping, and Others for the current month
                const queryExpenses = `
                    SELECT spending_category_id AS category_id, SUM(amount) AS total_spent
                    FROM transactions
                    WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
                    AND type = 'spending'
                    AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
                    GROUP BY spending_category_id;
                `;
                
                database.query(queryExpenses, [userId, currentMonth], (err, expenseRows) => {
                    if (err) {
                        console.error("Error fetching expenses:", err);
                        return res.status(500).json({ success: false, message: "Error fetching expenses" });
                    }

                    console.log("Expense Data:", expenseRows);

                    // Step 5: Calculate budget status for Food and Beverage, Shopping
                    const budgetStatus = budgetRows.map(budget => {
                        const expense = expenseRows.find(exp => exp.category_id === budget.category_id);
                        const spent = expense ? expense.total_spent : 0;
                        const percentage = (spent / budget.category_budget) * 100;

                        return {
                            category: budget.category_name,
                            categoryType: budget.category_type,
                            amountSpent: spent,
                            budgetAmount: budget.category_budget,
                            percentage: Math.round(percentage)
                        };
                    });

                    // Step 6: Calculate "Others" spending if there are categories in "Others"
                    if (otherCategoryIds.length > 0) {
                        const queryOtherExpenses = `
                            SELECT SUM(amount) AS total_spent
                            FROM transactions
                            WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
                            AND type = 'spending'
                            AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
                            AND spending_category_id IN (${otherCategoryIds.map(() => '?').join(',')})
                        `;
                        
                        database.query(queryOtherExpenses, [userId, currentMonth, ...otherCategoryIds], (err, otherExpenseRows) => {
                            if (err) {
                                console.error("Error fetching 'Other' expenses:", err);
                                return res.status(500).json({ success: false, message: "Error fetching 'Other' expenses" });
                            }

                            const totalOtherSpent = otherExpenseRows[0] ? otherExpenseRows[0].total_spent : 0;
                            const otherPercentage = (totalOtherSpent / totalOtherBudget) * 100;

                            budgetStatus.push({
                                category: "Other",
                                amountSpent: totalOtherSpent,
                                budgetAmount: totalOtherBudget,
                                percentage: Math.round(otherPercentage)
                            });

                            console.log("Final Budget Status:", budgetStatus);
                            res.json({ success: true, data: budgetStatus });
                        });
                    } else {
                        // If no "Others", finalize response without querying other expenses
                        res.json({ success: true, data: budgetStatus });
                    }
                });
            });
        });
    });
});


app.get("/GatewayApi/v1/getAllBudgetStatus", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    console.log("User ID:", userId);
    console.log("Current Month:", currentMonth);

    // Step 1: Retrieve budget_id and total_budget for the current month
    const queryMonthlyBudget = `
        SELECT budget_id, total_budget 
        FROM monthlybudget 
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?) 
        AND month = ?
    `;
    
    database.query(queryMonthlyBudget, [userId, currentMonth], (err, rows) => {
        if (err) {
            console.error("Error fetching monthly budget:", err);
            return res.status(500).json({ success: false, message: "Error fetching monthly budget" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "No budget found for the current month" });
        }

        const { budget_id, total_budget } = rows[0];
        console.log("Budget ID:", budget_id, "Total Budget:", total_budget);

        // Step 2: Retrieve all budget details and categories
        const queryBudgetDetails = `
            SELECT bd.category_id, bd.category_budget, bd.category_type, sc.category_name
            FROM budgetdetails bd
            JOIN spendingcategories sc ON bd.category_id = sc.category_id
            WHERE bd.budget_id = ?
        `;
        
        database.query(queryBudgetDetails, [budget_id], (err, budgetRows) => {
            if (err) {
                console.error("Error fetching budget details:", err);
                return res.status(500).json({ success: false, message: "Error fetching budget details" });
            }

            console.log("Budget Details:", budgetRows);

            // Step 3: Retrieve spending data for the current month
            const queryTotalExpenses = `
                SELECT SUM(amount) AS total_spent
                FROM transactions
                WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
                AND type = 'spending'
                AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
            `;
            
            database.query(queryTotalExpenses, [userId, currentMonth], (err, totalExpensesRow) => {
                if (err) {
                    console.error("Error fetching total expenses:", err);
                    return res.status(500).json({ success: false, message: "Error fetching total expenses" });
                }

                const totalSpent = totalExpensesRow[0]?.total_spent || 0;
                console.log("Total Spent for Current Month:", totalSpent);

                // Step 4: Retrieve spending data for each category
                const queryExpenses = `
                    SELECT spending_category_id AS category_id, SUM(amount) AS total_spent
                    FROM transactions
                    WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
                    AND type = 'spending'
                    AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
                    GROUP BY spending_category_id;
                `;
                
                database.query(queryExpenses, [userId, currentMonth], (err, expenseRows) => {
                    if (err) {
                        console.error("Error fetching expenses:", err);
                        return res.status(500).json({ success: false, message: "Error fetching expenses" });
                    }

                    console.log("Expense Data:", expenseRows);

                    // Step 5: Calculate budget status for all categories
                    const budgetStatus = budgetRows.map(budget => {
                        const expense = expenseRows.find(exp => exp.category_id === budget.category_id);
                        const spent = expense ? expense.total_spent : 0;
                        const percentage = (spent / budget.category_budget) * 100;

                        return {
                            category: budget.category_name,
                            categoryType: budget.category_type,
                            amountSpent: spent,
                            budgetAmount: budget.category_budget,
                            percentage: Math.round(percentage)
                        };
                    });

                    const totalPercentage = (totalSpent / total_budget) * 100;

                    console.log("Final Budget Status:", budgetStatus);

                    // Final response
                    res.json({
                        success: true,
                        data: {
                            totalBudget: total_budget,
                            totalSpent,
                            totalPercentage: Math.round(totalPercentage),
                            details: budgetStatus
                        }
                    });
                });
            });
        });
    });
});



//Endpoint untuk ngambil semua data transaksi bulan ini untuk di implementasiin ke chart
app.get("/GatewayApi/v1/getTransactionsCurrentMonth", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const currentMonth = new Date().getMonth() + 1; // Bulan (0-based, jadi tambahkan 1)
    const currentYear = new Date().getFullYear();

    // Langkah 1: Ambil account_id berdasarkan user_id
    const queryID = "SELECT account_id FROM accounts WHERE user_id = ?";
    database.query(queryID, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User or account not found" });
        }

        const accountId = rows[0].account_id;

        // Langkah 2: Ambil data transaksi untuk bulan dan tahun saat ini
        const queryTransactions = `
            SELECT 
                transaction_id, account_id, amount, transaction_date, type, 
                spending_category_id, earning_category_id, description
            FROM transactions
            WHERE account_id = ? 
                AND MONTH(transaction_date) = ? 
                AND YEAR(transaction_date) = ?;
        `;

        database.query(queryTransactions, [accountId, currentMonth, currentYear], (err, transactionRows) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: "Internal Server Error" });
            }

            res.json({ success: true, data: transactionRows });
        });
    });
});

app.get("/GatewayApi/v1/getTransactionsByMonth", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { month, year } = req.query;

    if (!month || !year) {
        return res.status(400).json({ success: false, message: "Month and year are required" });
    }

    // Langkah 1: Ambil account_id berdasarkan user_id
    const queryID = "SELECT account_id FROM accounts WHERE user_id = ?";
    database.query(queryID, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User or account not found" });
        }

        const accountId = rows[0].account_id;

        // Langkah 2: Ambil data transaksi berdasarkan account_id, bulan, dan tahun yang dipilih
        const queryTransactions = `
            SELECT 
                transaction_id, account_id, amount, transaction_date, type, 
                spending_category_id, earning_category_id, description
            FROM transactions
            WHERE account_id = ? 
                AND MONTH(transaction_date) = ? 
                AND YEAR(transaction_date) = ?;
        `;

        database.query(queryTransactions, [accountId, month, year], (err, transactionRows) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: "Internal Server Error" });
            }

            res.json({ success: true, data: transactionRows });
        });
    });
});

app.get("/GatewayApi/v1/getUserLatestTransactions", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = `
        SELECT transaction_id, account_id, amount, transaction_date, type, spending_category_id, earning_category_id, description
        FROM transactions
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
        ORDER BY transaction_date DESC
        LIMIT 4;  -- Adjust the limit as needed to fetch only the latest transactions
    `;

    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else {
            res.json({ success: true, data: rows });
        }
    });
});

//Ambil total spending
app.get("/GatewayApi/v1/getSumMonthSpending", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const currentDate = new Date();
    const currentMonth = currentDate.getMonth() + 1; // JavaScript months are 0-indexed
    const currentYear = currentDate.getFullYear();

    const query = `
        SELECT SUM(amount) AS totalSpending
        FROM transactions
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
            AND type = 'spending'
            AND MONTH(transaction_date) = ?
            AND YEAR(transaction_date) = ?
    `;

    database.query(query, [userId, currentMonth, currentYear], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length > 0) {
            res.json({ success: true, data: rows[0] });
        } else {
            res.status(404).json({ success: false, message: "No spending data found for the current month" });
        }
    });
});



//Ambil total earning
app.get("/GatewayApi/v1/getSumMonthEarning", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const currentDate = new Date();
    const currentMonth = currentDate.getMonth() + 1; // Months are 0-based in JavaScript
    const currentYear = currentDate.getFullYear();

    const query = `
        SELECT SUM(amount) AS totalEarning
        FROM transactions
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?) 
            AND type = 'earning'
            AND MONTH(transaction_date) = ?
            AND YEAR(transaction_date) = ?
    `;

    database.query(query, [userId, currentMonth, currentYear], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length > 0) {
            res.json({ success: true, data: rows[0] });
        } else {
            res.status(404).json({ success: false, message: "No earnings found for the current month" });
        }
    });
});

//Masukkan Pengeluaran
// Masukkan Pengeluaran
app.post("/GatewayApi/v1/postSpending", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { amount, transaction_date, spending_category_id, description } = req.body;

    if (!amount || amount <= 0 || !transaction_date || !spending_category_id) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }

    const queryInsert = `
        INSERT INTO transactions (account_id, amount, transaction_date, type, spending_category_id, description)
        SELECT account_id, ?, ?, 'spending', ?, ?
        FROM accounts WHERE user_id = ?
    `;

    database.query(queryInsert, [amount, transaction_date, spending_category_id, description, userId], (err, result) => {
        if (err) {
            console.error("Error inserting spending:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (result.affectedRows > 0) {
            // Update balance setelah pengeluaran berhasil disimpan
            const queryUpdateBalance = `
                UPDATE accounts
                SET balance = (
                    SELECT COALESCE(SUM(CASE WHEN type = 'earning' THEN amount ELSE -amount END), 0)
                    FROM transactions WHERE account_id = accounts.account_id
                )
                WHERE user_id = ?
            `;

            database.query(queryUpdateBalance, [userId], (err) => {
                if (err) {
                    console.error("Error updating balance:", err);
                    return res.status(500).json({ success: false, message: "Failed to update balance" });
                }

                res.json({ success: true, message: "Transaction successfully added and balance updated" });
            });
        } else {
            res.status(400).json({ success: false, message: "Failed to add transaction" });
        }
    });
});



//Masukkan Pendapatan
// Masukkan Pendapatan
app.post("/GatewayApi/v1/postEarning", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { amount, transaction_date, earning_category_id, description } = req.body;

    if (!amount || amount <= 0 || !transaction_date || !earning_category_id) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }

    const queryInsert = `
        INSERT INTO transactions (account_id, amount, transaction_date, type, earning_category_id, description)
        SELECT account_id, ?, ?, 'earning', ?, ?
        FROM accounts WHERE user_id = ?
    `;

    database.query(queryInsert, [amount, transaction_date, earning_category_id, description, userId], (err, result) => {
        if (err) {
            console.error("Error inserting earning:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (result.affectedRows > 0) {
            // Update balance setelah pendapatan berhasil disimpan
            const queryUpdateBalance = `
                UPDATE accounts
                SET balance = (
                    SELECT COALESCE(SUM(CASE WHEN type = 'earning' THEN amount ELSE -amount END), 0)
                    FROM transactions WHERE account_id = accounts.account_id
                )
                WHERE user_id = ?
            `;

            database.query(queryUpdateBalance, [userId], (err) => {
                if (err) {
                    console.error("Error updating balance:", err);
                    return res.status(500).json({ success: false, message: "Failed to update balance" });
                }

                res.json({ success: true, message: "Transaction successfully added and balance updated" });
            });
        } else {
            res.status(400).json({ success: false, message: "Failed to add transaction" });
        }
    });
});


app.get("/GatewayApi/v1/getUserTransactions", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = `
        SELECT transaction_id, account_id, amount, transaction_date, type, spending_category_id, earning_category_id, description
        FROM transactions
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
        ORDER BY transaction_date DESC
    `;

    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else {
            res.json({ success: true, data: rows });
        }
    });
});

app.get("/GatewayApi/v1/getRecentActivity", authenticateToken, (req, res) => {
    const { month, year, type } = req.query; // Tambahkan filter type
    const userId = req.user.id;

    let query = `
        SELECT transaction_id, account_id, amount, transaction_date, type, spending_category_id, earning_category_id, description
        FROM transactions
        WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
    `;

    const params = [userId];

    // Tambahkan filter untuk bulan dan tahun jika ada
    if (month && year) {
        query += " AND MONTH(transaction_date) = ? AND YEAR(transaction_date) = ?";
        params.push(month, year);
    } else if (year) {
        query += " AND YEAR(transaction_date) = ?";
        params.push(year);
    }

    // Tambahkan filter untuk tipe transaksi jika ada
    if (type) {
        query += " AND type = ?";
        params.push(type);
    }

    query += " ORDER BY transaction_date DESC";

    database.query(query, params, (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            res.status(500).json({ success: false, message: "Database error" });
        } else {
            res.json({ success: true, data: rows });
        }
    });
});

app.get("/GatewayApi/v1/getAllTransactionsUser", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { month, year } = req.query;

    // Langkah 1: Ambil account_id berdasarkan user_id
    const queryID = "SELECT account_id FROM accounts WHERE user_id = ?";
    database.query(queryID, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User or account not found" });
        }

        const accountId = rows[0].account_id;

        // Langkah 2: Susun query transaksi berdasarkan parameter yang diberikan
        let queryTransactions = `
            SELECT 
                transaction_id, account_id, amount, transaction_date, type, 
                spending_category_id, earning_category_id, description
            FROM transactions
            WHERE account_id = ?
        `;
        const queryParams = [accountId];

        // Tambahkan filter bulan jika disediakan
        if (month) {
            queryTransactions += " AND MONTH(transaction_date) = ?";
            queryParams.push(month);
        }

        // Tambahkan filter tahun jika disediakan
        if (year) {
            queryTransactions += " AND YEAR(transaction_date) = ?";
            queryParams.push(year);
        }

        queryTransactions += " ORDER BY transaction_date DESC"; // Urutkan berdasarkan tanggal

        // Jalankan query transaksi
        database.query(queryTransactions, queryParams, (err, transactionRows) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ success: false, message: "Internal Server Error" });
            }

            res.json({ success: true, data: transactionRows });
        });
    });
});


//ENDPOINT SET Budget
// Endpoint untuk mengecek apakah budget untuk bulan ini sudah ada
app.get("/GatewayApi/v1/checkMonthlyBudget", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    try {
        // Ambil account_id berdasarkan user_id
        const accountQuery = "SELECT account_id FROM accounts WHERE user_id = ?";
        const accountRows = await query(accountQuery, [userId]);

        if (accountRows.length === 0) {
            return res.status(404).json({ success: false, message: "Account not found" });
        }

        const accountId = accountRows[0].account_id;

        // Cek apakah ada data budget untuk bulan ini
        const budgetQuery = `
            SELECT budget_id, total_budget, month, created_at
            FROM monthlybudget
            WHERE account_id = ? AND month = ?
        `;
        const budgetRows = await query(budgetQuery, [accountId, currentMonth]);

        if (budgetRows.length > 0) {
            return res.json({ success: true, exists: true, data: budgetRows[0] }); // Data ditemukan
        } else {
            return res.json({ success: true, exists: false }); // Data tidak ditemukan
        }
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
// Endpoint untuk menambahkan data monthly budget
app.post("/GatewayApi/v1/addMonthlyBudget", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { total_budget } = req.body;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    if (!total_budget || total_budget <= 0) {
        return res.status(400).json({ success: false, message: "Invalid total budget" });
    }

    try {
        // Ambil account_id berdasarkan user_id
        const accountQuery = "SELECT account_id FROM accounts WHERE user_id = ?";
        const accountRows = await query(accountQuery, [userId]);

        if (accountRows.length === 0) {
            return res.status(404).json({ success: false, message: "Account not found" });
        }

        const accountId = accountRows[0].account_id;

        // Periksa apakah data untuk bulan ini sudah ada
        const checkBudgetQuery = `
            SELECT * FROM monthlybudget
            WHERE account_id = ? AND month = ?
        `;
        const checkBudgetRows = await query(checkBudgetQuery, [accountId, currentMonth]);

        if (checkBudgetRows.length > 0) {
            return res.status(400).json({ success: false, message: "Monthly budget already exists" });
        }

        // Masukkan data baru ke tabel monthlybudget
        const insertBudgetQuery = `
            INSERT INTO monthlybudget (account_id, month, total_budget, created_at)
            VALUES (?, ?, ?, NOW())
        `;
        const insertResult = await query(insertBudgetQuery, [accountId, currentMonth, total_budget]);

        if (insertResult.affectedRows > 0) {
            res.json({ success: true, message: "Monthly budget added successfully" });
        } else {
            res.status(500).json({ success: false, message: "Failed to add monthly budget" });
        }
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
// Endpoint untuk memperbarui budget bulanan
app.put("/GatewayApi/v1/updateMonthlyBudget", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { total_budget } = req.body;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    if (!total_budget || total_budget <= 0) {
        return res.status(400).json({ success: false, message: "Invalid total budget" });
    }

    try {
        // Ambil account_id berdasarkan user_id
        const accountQuery = "SELECT account_id FROM accounts WHERE user_id = ?";
        const accountRows = await query(accountQuery, [userId]);

        if (accountRows.length === 0) {
            return res.status(404).json({ success: false, message: "Account not found" });
        }

        const accountId = accountRows[0].account_id;

        // Periksa apakah data budget untuk bulan saat ini ada
        const checkBudgetQuery = `
            SELECT budget_id FROM monthlybudget
            WHERE account_id = ? AND month = ?
        `;
        const budgetRows = await query(checkBudgetQuery, [accountId, currentMonth]);

        if (budgetRows.length === 0) {
            return res.status(404).json({ success: false, message: "No budget found for the current month" });
        }

        const budgetId = budgetRows[0].budget_id;

        // Perbarui total_budget untuk bulan ini
        const updateBudgetQuery = `
            UPDATE monthlybudget
            SET total_budget = ?, created_at = NOW()
            WHERE budget_id = ?
        `;
        const updateResult = await query(updateBudgetQuery, [total_budget, budgetId]);

        if (updateResult.affectedRows > 0) {
            res.json({ success: true, message: "Budget updated successfully" });
        } else {
            res.status(500).json({ success: false, message: "Failed to update budget" });
        }
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
//Endpoint deleteMonthlyBudget 
app.delete("/GatewayApi/v1/deleteMonthlyBudget", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    try {
        // Step 1: Ambil account_id berdasarkan user_id
        const accountQuery = "SELECT account_id FROM accounts WHERE user_id = ?";
        const accountRows = await query(accountQuery, [userId]);

        if (accountRows.length === 0) {
            return res.status(404).json({ success: false, message: "Account not found" });
        }

        const accountId = accountRows[0].account_id;

        // Step 2: Cek apakah monthlybudget ada untuk bulan ini
        const monthlyBudgetQuery = `
            SELECT budget_id FROM monthlybudget
            WHERE account_id = ? AND month = ?
        `;
        const monthlyBudgetRows = await query(monthlyBudgetQuery, [accountId, currentMonth]);

        if (monthlyBudgetRows.length === 0) {
            return res.status(404).json({ success: false, message: "No monthly budget found for this month" });
        }

        const budgetId = monthlyBudgetRows[0].budget_id;

        // Step 3: Cek apakah ada data terkait di tabel budgetdetails
        const budgetDetailsQuery = `
            SELECT * FROM budgetdetails WHERE budget_id = ?
        `;
        const budgetDetailsRows = await query(budgetDetailsQuery, [budgetId]);

        if (budgetDetailsRows.length > 0) {
            // Hapus data terkait di tabel budgetdetails
            const deleteBudgetDetailsQuery = `
                DELETE FROM budgetdetails WHERE budget_id = ?
            `;
            await query(deleteBudgetDetailsQuery, [budgetId]);
        }

        // Step 4: Hapus data di tabel monthlybudget
        const deleteMonthlyBudgetQuery = `
            DELETE FROM monthlybudget WHERE budget_id = ?
        `;
        const deleteResult = await query(deleteMonthlyBudgetQuery, [budgetId]);

        if (deleteResult.affectedRows > 0) {
            return res.json({ success: true, message: "Monthly budget and related details deleted successfully" });
        } else {
            return res.status(500).json({ success: false, message: "Failed to delete monthly budget" });
        }
    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

//endpoint detailbudget
// Endpoint untuk mengambil semua budget details berdasarkan budget_id
app.get("/GatewayApi/v1/budgetDetails/:budget_id", authenticateToken, async (req, res) => {
    const { budget_id } = req.params;

    if (!budget_id) {
        return res.status(400).json({ success: false, message: "Budget ID is required" });
    }

    try {
        // Query untuk mengambil data budget details
        const sql = `
            SELECT bd.detail_id, bd.category_id, sc.category_name, bd.category_budget
            FROM budgetdetails bd
            INNER JOIN spendingcategories sc ON bd.category_id = sc.category_id
            WHERE bd.budget_id = ?
        `;
        const budgetDetails = await query(sql, [budget_id]);

        if (budgetDetails && budgetDetails.length > 0) {
            res.json({ success: true, data: budgetDetails });
        } else {
            res.json({
                success: true,
                data: [],
                message: "No budget details found for this Budget ID. You can start adding details now!",
            });
        }
    } catch (error) {
        console.error("Database error:", error.message);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

// Endpoint untuk mengambil nama kategori dari tabel spendingcategories
app.get("/GatewayApi/v1/getCategories", authenticateToken, async (req, res) => {
    try {
        const queryCategories = "SELECT category_id, category_name FROM spendingcategories";
        const categories = await query(queryCategories);

        if (categories.length > 0) {
            res.json({ success: true, data: categories });
        } else {
            res.status(404).json({ success: false, message: "No categories found" });
        }
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.post("/GatewayApi/v1/replaceBudgetDetails", authenticateToken, (req, res) => {
    const { budget_id, details } = req.body;
  
    if (!budget_id || !Array.isArray(details) || details.length === 0) {
      return res.status(400).json({ success: false, message: "No details provided" });
    }
  
    database.beginTransaction((err) => {
      if (err) {
        console.error("Transaction start error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }
  
      // Step 1: Delete existing budget details
      const deleteQuery = "DELETE FROM budgetdetails WHERE budget_id = ?";
      database.query(deleteQuery, [budget_id], (deleteErr) => {
        if (deleteErr) {
          console.error("Delete error:", deleteErr);
          return database.rollback(() => {
            res.status(500).json({ success: false, message: "Internal Server Error" });
          });
        }
  
        // Step 2: Insert new budget details
        const insertQuery = `
          INSERT INTO budgetdetails (budget_id, category_id, category_budget, created_at)
          VALUES (?, ?, ?, NOW())
        `;
  
        const insertPromises = details.map((detail) => {
          const { category_id, category_budget } = detail;
  
          // Validation
          if (!category_id || !category_budget || category_budget <= 0) {
            return Promise.reject(new Error("Invalid detail data"));
          }
  
          return new Promise((resolve, reject) => {
            database.query(insertQuery, [budget_id, category_id, category_budget], (insertErr) => {
              if (insertErr) {
                reject(insertErr);
              } else {
                resolve();
              }
            });
          });
        });
  
        // Handle all insertions
        Promise.all(insertPromises)
          .then(() => {
            database.commit((commitErr) => {
              if (commitErr) {
                console.error("Commit error:", commitErr);
                return database.rollback(() => {
                  res.status(500).json({ success: false, message: "Internal Server Error" });
                });
              }
  
              res.json({ success: true, message: "Budget details replaced successfully" });
            });
          })
          .catch((insertErr) => {
            console.error("Insert error:", insertErr);
            database.rollback(() => {
              res.status(500).json({ success: false, message: "Internal Server Error" });
            });
          });
      });
    });
  });


//ENPOINT Notifikasi
//ngambil notif
app.get("/GatewayApi/v1/getnotifications", authenticateToken, (req, res) => {
    const userId = req.user.id; // ID pengguna dari token
    const query = `
      SELECT 
          notification_id,
          message, 
          created_at, 
          is_read 
      FROM 
          notifications 
      WHERE 
          user_id = ?
      ORDER BY 
          created_at DESC;
    `;

    // Jalankan query database
    database.query(query, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err.message);
            return res.status(500).json({
                success: false,
                message: "Gagal mengambil notifikasi. Silakan coba lagi nanti.",
            });
        }

        // Cek jika tidak ada notifikasi
        if (rows.length === 0) {
            return res.status(404).json({
                success: true, // Masih sukses karena ini bukan error
                message: "Tidak ada notifikasi ditemukan.",
                data: [], // Kembalikan data kosong
            });
        }

        // Kembalikan notifikasi
        res.status(200).json({
            success: true,
            message: "Notifikasi berhasil diambil.",
            data: rows,
        });
    });
});

//Endpoint untuk mengambil 3 notifikasi terbaru
app.get("/GatewayApi/v1/getnotificationsLimit", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const query = `
      SELECT 
          notification_id,
          message, 
          created_at, 
          is_read 
      FROM 
          notifications 
      WHERE 
          user_id = ?
      ORDER BY 
          created_at DESC
      LIMIT 3;
    `;
    const countQuery = `
      SELECT COUNT(*) as total
      FROM notifications
      WHERE user_id = ?;
    `;
  
    database.query(query, [userId], (err, rows) => {
      if (err) {
        console.error("Database error:", err.message);
        return res.status(500).json({
          success: false,
          message: "Gagal mengambil notifikasi. Silakan coba lagi nanti.",
        });
      }
  
      database.query(countQuery, [userId], (errCount, countResult) => {
        if (errCount) {
          console.error("Database error:", errCount.message);
          return res.status(500).json({
            success: false,
            message: "Gagal menghitung notifikasi.",
          });
        }
  
        const totalNotifications = countResult[0].total;
  
        // Cek jika tidak ada notifikasi
        if (rows.length === 0) {
          return res.status(404).json({
            success: true,
            message: "Tidak ada notifikasi ditemukan.",
            data: [],
            totalNotifications: totalNotifications,
          });
        }
  
        // Kembalikan notifikasi
        res.status(200).json({
          success: true,
          message: "Notifikasi berhasil diambil.",
          data: rows,
          totalNotifications: totalNotifications,
        });
      });
    });
  });
  

//Read notif
app.post('/GatewayApi/v1/markAsRead/:notificationId', authenticateToken, async (req, res) => {
    const { notificationId } = req.params;

    try {
        // Perbarui status notifikasi menjadi dibaca
        const result = await database.query(
            `UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?`,
            [notificationId, req.user.id]
        );

        if (result.affectedRows === 0) {
            // Jika tidak ada baris yang diperbarui, mungkin ID salah atau notifikasi tidak milik pengguna ini
            return res.status(404).json({
                success: false,
                message: "Notifikasi tidak ditemukan atau bukan milik pengguna.",
            });
        }

        res.status(200).json({
            success: true,
            message: "Notifikasi berhasil ditandai sebagai dibaca.",
        });
    } catch (err) {
        console.error("Error marking notification as read:", err.message);
        res.status(500).json({
            success: false,
            message: "Terjadi kesalahan pada server. Silakan coba lagi.",
        });
    }
});

//all read
app.post("/GatewayApi/v1/markAllAsRead", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await database.query(
        `UPDATE notifications SET is_read = 1 WHERE user_id = ?`,
        [userId]
        );

        res.status(200).json({
            success: true,
            message: "Semua notifikasi berhasil ditandai sebagai dibaca.",
        });
        } catch (err) {
        console.error("Error marking all notifications as read:", err.message);
        res.status(500).json({
        success: false,
        message: "Terjadi kesalahan pada server.",
        });
    }
});

//ngasih notif buat budget dan budgetdetails
app.post("/GatewayApi/v1/checkAndNotifyBudget", authenticateToken, async (req, res) => {
    const userId = req.user.id; // Ambil ID pengguna dari token
    const { category_id, amount } = req.body; // Ambil ID kategori dan jumlah pengeluaran
    const currentMonth = new Date().toISOString().slice(0, 7); // Format 'YYYY-MM'

    try {
        console.log("STEP 1: Memulai pengecekan budget untuk userId:", userId, "currentMonth:", currentMonth);

        // Ambil semua kategori dan buat map untuk pencocokan
        const queryCategories = "SELECT category_id, category_name FROM spendingcategories";
        const categories = await query(queryCategories);
        const categoryMap = categories.reduce((map, category) => {
            map[category.category_id] = category.category_name;
            return map;
        }, {});

        // Step 1: Ambil budget_id dan total_budget untuk bulan ini
        const queryMonthlyBudget = `
            SELECT budget_id, total_budget 
            FROM monthlybudget 
            WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?) 
            AND month = ?
        `;
        const [monthlyBudgetResult] = await query(queryMonthlyBudget, [userId, currentMonth]);
        console.log("STEP 2: Hasil monthlyBudgetResult:", monthlyBudgetResult);

        if (!monthlyBudgetResult) {
            console.warn("STEP 2 WARNING: No budget found for the current month.");
            return res.status(404).json({ success: false, message: "No budget found for the current month" });
        }

        const { budget_id, total_budget } = monthlyBudgetResult;

        // Step 2: Ambil pengeluaran total untuk bulan ini
        const queryTotalExpenses = `
            SELECT SUM(amount) AS total_spent
            FROM transactions
            WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
            AND type = 'spending'
            AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
        `;
        const [totalExpensesResult] = await query(queryTotalExpenses, [userId, currentMonth]);
        const totalSpent = totalExpensesResult?.total_spent || 0;
        const totalPercentageUsed = (totalSpent / total_budget) * 100;
        console.log("STEP 3: Total spent:", totalSpent, "Total percentage used:", totalPercentageUsed);

        // Step 3: Ambil pengeluaran untuk kategori tertentu
        const queryCategoryExpenses = `
            SELECT SUM(amount) AS total_spent
            FROM transactions
            WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = ?)
            AND type = 'spending'
            AND spending_category_id = ?
            AND DATE_FORMAT(transaction_date, '%Y-%m') = ?
        `;
        const [categoryExpensesResult] = await query(queryCategoryExpenses, [userId, category_id, currentMonth]);
        const categorySpent = categoryExpensesResult?.total_spent || 0;
        console.log("STEP 4: Category spent:", categorySpent, "for category_id:", category_id);

        // Step 4: Ambil budget untuk kategori ini (jika ada)
        const queryCategoryBudget = `
            SELECT category_budget 
            FROM budgetdetails 
            WHERE budget_id = ? AND category_id = ?
        `;
        const [categoryBudgetResult] = await query(queryCategoryBudget, [budget_id, category_id]);

        if (categoryBudgetResult) {
            const { category_budget } = categoryBudgetResult;
            const categoryPercentageUsed = (categorySpent / category_budget) * 100;
            console.log("STEP 5: Category percentage used:", categoryPercentageUsed);

            const categoryName = categoryMap[category_id] || `Kategori ${category_id}`;

            // Cek anggaran kategori dan tambahkan notifikasi jika diperlukan
            if (categoryPercentageUsed >= 50 && categoryPercentageUsed < 100) {
                const notificationContext = `category-50%-${category_id}`;
                const [notificationExists] = await query(
                    "SELECT 1 FROM notifications WHERE user_id = ? AND notification_context = ?",
                    [userId, notificationContext]
                );

                if (!notificationExists) {
                    console.log("STEP 6: Adding 50% category budget notification.");
                    await query(
                        "INSERT INTO notifications (user_id, message, created_at, is_read, notification_context) VALUES (?, ?, NOW(), 0, ?)",
                        [userId, `Anggaran untuk kategori ${categoryName} telah terpakai 50%.`, notificationContext]
                    );
                }
            }

            if (categoryPercentageUsed >= 100) {
                const notificationContext = `category-100%-${category_id}`;
                const [notificationExists] = await query(
                    "SELECT 1 FROM notifications WHERE user_id = ? AND notification_context = ?",
                    [userId, notificationContext]
                );

                if (!notificationExists) {
                    console.log("STEP 7: Adding 100% category budget notification.");
                    await query(
                        "INSERT INTO notifications (user_id, message, created_at, is_read, notification_context) VALUES (?, ?, NOW(), 0, ?)",
                        [userId, `Anggaran untuk kategori ${categoryName} telah habis.`, notificationContext]
                    );
                }
            }
        } else {
            console.log("STEP 5: No budget found for category_id:", category_id, "- skipping category checks.");
        }

        // Step 5: Cek total anggaran bulanan dan tambahkan notifikasi jika diperlukan
        if (totalPercentageUsed >= 50 && totalPercentageUsed < 100) {
            const notificationContext = `monthly-50%-${budget_id}`;
            const [notificationExists] = await query(
                "SELECT 1 FROM notifications WHERE user_id = ? AND notification_context = ?",
                [userId, notificationContext]
            );

            if (!notificationExists) {
                console.log("STEP 8: Adding 50% monthly budget notification.");
                await query(
                    "INSERT INTO notifications (user_id, message, created_at, is_read, notification_context) VALUES (?, ?, NOW(), 0, ?)",
                    [userId, "Anggaran bulanan Anda telah terpakai 50%.", notificationContext]
                );
            }
        }

        if (totalPercentageUsed >= 100) {
            const notificationContext = `monthly-100%-${budget_id}`;
            const [notificationExists] = await query(
                "SELECT 1 FROM notifications WHERE user_id = ? AND notification_context = ?",
                [userId, notificationContext]
            );

            if (!notificationExists) {
                console.log("STEP 9: Adding 100% monthly budget notification.");
                await query(
                    "INSERT INTO notifications (user_id, message, created_at, is_read, notification_context) VALUES (?, ?, NOW(), 0, ?)",
                    [userId, "Anggaran bulanan Anda telah habis.", notificationContext]
                );
            }
        }

        res.json({
            success: true,
            message: "Budget and notifications checked and updated.",
        });
    } catch (error) {
        console.error("Error checking and notifying budget:", error.message);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


//DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN//

app.post("/GatewayApi/v1/deleteAccount", authenticateToken, async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ success: false, message: "Password is required to delete the account." });
    }

    try {
        const userId = req.user.id;

        // Step 1: Ambil informasi pengguna
        const userQuery = "SELECT password FROM users WHERE user_id = ?";
        const [userResult] = await query(userQuery, [userId]);

        if (!userResult) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const isMatch = await bcrypt.compare(password, userResult.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Incorrect password." });
        }

        // Step 2: Ambil account_id dari tabel accounts
        const accountQuery = "SELECT account_id FROM accounts WHERE user_id = ?";
        const [accountResult] = await query(accountQuery, [userId]);

        if (!accountResult) {
            return res.status(404).json({ success: false, message: "Account not found." });
        }

        const accountId = accountResult.account_id;

        // Step 3: Ambil semua budget_id dari monthlybudget berdasarkan account_id
        const budgetQuery = "SELECT budget_id FROM monthlybudget WHERE account_id = ?";
        const budgetResults = await query(budgetQuery, [accountId]);

        if (budgetResults.length > 0) {
            const budgetIds = budgetResults.map((row) => row.budget_id);

            // Step 4: Hapus detail budget berdasarkan budget_id
            const deleteBudgetDetailsQuery = `
                DELETE FROM budgetdetails WHERE budget_id IN (${budgetIds.map(() => "?").join(",")})
            `;
            await query(deleteBudgetDetailsQuery, budgetIds);

            // Step 5: Hapus monthlybudget berdasarkan account_id
            const deleteMonthlyBudgetQuery = "DELETE FROM monthlybudget WHERE account_id = ?";
            await query(deleteMonthlyBudgetQuery, [accountId]);
        }

        // Step 6: Hapus notifikasi berdasarkan user_id
        const deleteNotificationsQuery = "DELETE FROM notifications WHERE user_id = ?";
        await query(deleteNotificationsQuery, [userId]);

        // Step 7: Hapus transaksi berdasarkan account_id
        const deleteTransactionsQuery = "DELETE FROM transactions WHERE account_id = ?";
        await query(deleteTransactionsQuery, [accountId]);

        // Step 8: Hapus data dari tabel accounts berdasarkan user_id/account_id
        const deleteAccountQuery = "DELETE FROM accounts WHERE account_id = ?";
        await query(deleteAccountQuery, [accountId]);

        // Step 9: Hapus data pengguna dari tabel users berdasarkan user_id
        const deleteUserQuery = "DELETE FROM users WHERE user_id = ?";
        await query(deleteUserQuery, [userId]);

        res.json({
            success: true,
            message: "Account and all associated data have been successfully deleted.",
        });
    } catch (error) {
        console.error("Error during account deletion:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
//DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN////DELETE AKUN//


//Belom Fix
app.post("/GatewayApi/v1/postAllNotifications", authenticateToken, (req, res) => {
    const userId = req.user.id;
    const queryNewNotifications = `
      SELECT 
          t.transaction_id AS notification_id,
          CASE 
              WHEN t.type = 'spending' THEN CONCAT('Pengeluaran tercatat sebesar Rp. ', t.amount, ' pada kategori ', s.spending_category_id)
              WHEN t.type = 'earning' THEN CONCAT('Pemasukan sebesar Rp. ', t.amount, ' telah masuk dari kategori ', e.earning_category_id)
              ELSE 'Transaksi tidak dikenali'
          END AS message,
          t.transaction_date AS created_at
      FROM 
          transactions t
     JOIN spending_categories s ON t.spending_category_id = s.spending_category_id
     JOIN earning_categories e ON t.earning_category_id = e.earning_category_id
      WHERE 
          t.transaction_id NOT IN (SELECT notification_id FROM notifications)
          AND t.account_id IN (SELECT account_id FROM accounts WHERE user_id = ?) 
      ORDER BY t.transaction_date DESC;
    `;

    database.query(queryNewNotifications, [userId], (err, rows) => {
        if (err) {
            console.error("Database error:", err.message);
            return res.status(500).json({
                success: false,
                message: "Internal Server Error. Unable to retrieve new notifications.",
            });
        }
        const newNotifications = rows.map((row) => [
            row.notification_id,
            userId,
            row.message,
            row.created_at,
            0,
        ]);
        const queryUserJoinedNotification = `
          SELECT user_id, created_at 
          FROM users 
          WHERE user_id = ? AND DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') = DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i');
        `;

        database.query(queryUserJoinedNotification, [userId], (joinErr, joinRows) => {
            if (joinErr) {
                console.error("Database error on join check:", joinErr.message);
                return res.status(500).json({
                    success: false,
                    message: "Internal Server Error. Unable to check user join status.",
                });
            }
            if (joinRows.length > 0) {
                newNotifications.push([
                    welcome_$,{userId},
                    userId,
                    "Selamat bergabung di Budgetin! Semoga Anda dapat mengeksplorasi transaksi Anda dengan nyaman.",
                    new Date(),
                    0,
                ]);
            }

            const insertNotificationsQuery = `
              INSERT INTO notifications (notification_id, user_id, message, created_at, is_read)
              VALUES ?
              ON DUPLICATE KEY UPDATE notification_id = notification_id;
            `;
            if (newNotifications.length === 0) {
                return res.status(200).json({
                    success: true,
                    message: "No new notifications to add.",
                });
            }

            database.query(insertNotificationsQuery, [newNotifications], (insertErr) => {
                if (insertErr) {
                    console.error("Database insert error:", insertErr.message);
                    return res.status(500).json({
                        success: false,
                        message: "Internal Server Error. Unable to add new notifications.",
                    });
                }
                res.status(200).json({
                    success: true,
                    message: "New notifications added successfully.",
                    data: rows.concat(joinRows),
                });
            });
        });
    });
});

//Definisiin port yang dipake
app.listen(62542, () => {
    console.log("Server is running on port 62542");
});