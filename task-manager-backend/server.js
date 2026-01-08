require("dotenv").config();
const os = require("os");
const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const db = require("./db");
const app = express();
const nodemailer = require("nodemailer");
const pug = require("pug");
const port = process.env.PORT;

function getEth0IP() {
  const nets = os.networkInterfaces();
  if (!nets.enp0s3) {
    throw new Error("eth0 interface not found");
  }
  for (const net of nets.enp0s3) {
    if (net.family === "IPv4" && !net.internal) {
      return net.address;
    }
  }
  throw new Error("No IPv4 address found on eth0");
}

// Usage
const HOST = getEth0IP();

app.use(
  cors({
    origin: ["http://" + HOST, "http://127.0.0.1"],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "x-csrf-token"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      maxAge: 1000 * 60 * 60, // 1 hour
      // domain: process.env.CORS_ORIGIN.split('://')[1].split(':')[0]
    },
  })
);

function requireLogin(req, res, next) {
  if (!req.cookies || !req.cookies["connect.sid"]) {
    return res.status(403).json({ error: "Not authenticated" });
  }
  next();
}

function validateToken(req, res, next) {
  // Generate a new token if one doesn't exist in the session
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  // For POST requests, validate the token
  if (req.method === "POST") {
    const tokenFromHeader = req.headers["x-csrf-token"];
    console.log("Session token:", req.session.csrfToken);
    if (!tokenFromHeader || tokenFromHeader !== req.session.csrfToken) {
      return res.status(403).json({ error: "Invalid or missing CSRF token" });
    }
    // Regenerate the token after successful validation to prevent reuse
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  next();
}

// Create transporter
const transporter = nodemailer.createTransport({
  host: "127.0.0.1", // Postfix or Mailhog
  port: 1025, // Postfix SMTP port or Mailhog
  secure: false, // Use TLS if needed
});

// Function to send reset email
const sendResetEmail = async (email, resetToken) => {
  const resetUrl = `${process.env.CORS_ORIGIN}/reset-password?token=${resetToken}`;
  const mailOptions = {
    from: "noreply@yourdomain.com",
    to: email,
    subject: "Password Reset",
    html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. Link expires in 1 hour.</p>`,
  };
  await transporter.sendMail(mailOptions);
};

// CSRF Token Endpoint
app.get("/csrf-token", (req, res) => {
  console.log("CGDDFDSHJS", req.session.csrfToken);
  if (!req.session.csrfToken) {
    console.log("No CSRF token in session");
    return res.status(401).json({ error: "No active session or CSRF token" });
  }
  res.json({ csrfToken: req.session.csrfToken });
});

// Routes
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;
  const query =
    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
  db.query(query, [username, password, email], (err, result) => {
    if (err) {
      console.error(err);
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ error: "Email already registered" });
      }
      return res.status(500).json({ error: "Error registering user" });
    }
    res.json({ message: "User registered successfully" });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const query = "SELECT * FROM users WHERE email = ? AND password = ?";
  db.query(query, [email, password], (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Error logging in" });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const user = results[0];
    req.session.userID = user.id;
    req.session.isAdmin = user.isAdmin;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    console.log(req.session.csrfToken);
    req.session.save((err) => {
      if (err) console.log("Session save error:", err);
    });
    const dashboard = user.isAdmin ? "admin" : "user";
    res.json({ message: "Login successful", dashboard });
  });
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const [user] = await db
    .promise()
    .query("SELECT * FROM users WHERE email = ?", [email]);
  if (!user.length) {
    return res.status(404).json({ error: "User not found" });
  }
  const resetToken = crypto.randomBytes(32).toString("hex");
  // const hashedToken = await bcrypt.hash(resetToken, 12);
  const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await db
    .promise()
    .query(
      "UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?",
      [resetToken, expiry, email]
    );
  await sendResetEmail(email, resetToken);
  res.json({ message: "Reset email sent" });
});

app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  // const hashedToken = await bcrypt.hash(token, 12);
  const [user] = await db
    .promise()
    .query(
      "SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > NOW()",
      [token]
    );
  if (!user.length)
    return res.status(400).json({ error: "Invalid or expired token" });
  // const hashedPassword = await bcrypt.hash(newPassword, 12);
  db.query(
    "UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?",
    [newPassword, user[0].id]
  );
  res.json({ message: "Password reset successful" });
});

app.get("/me", requireLogin, (req, res) => {
  console.log("Session ID:", req.session.id);
  db.query(
    "SELECT username, email, id, isAdmin FROM users WHERE id = ?",
    [req.session.userID],
    (err, rows) => {
      if (err || rows.length === 0) {
        return res.status(401).json({ error: "Invalid session" });
      }
      const user = rows[0];
      const isAdmin = rows[0].isAdmin;
      if (isAdmin == 1) {
        return res.status(401).json({ error: "Not authorized" });
      } else {
        req.user = rows[0];
        res.json({
          username: user.username,
          email: user.email,
          role: user.isAdmin ? "admin" : "user",
        });
      }
    }
  );
});

app.get("/adminMe", requireLogin, (req, res) => {
  db.query(
    "SELECT username, email, id, isAdmin FROM users WHERE id = ?",
    [req.session.userID],
    (err, rows) => {
      if (err || rows.length === 0) {
        return res.status(401).json({ error: "Invalid session" });
      }
      const user = rows[0];
      const isAdmin = rows[0].isAdmin;
      if (isAdmin == 0) {
        return res.status(401).json({ error: "Not authorized" });
      } else {
        req.user = rows[0];
        res.json({
          username: req.user.username,
          email: req.user.email,
          role: user.isAdmin ? "admin" : "user",
        });
      }
    }
  );
});

app.post("/change-password", requireLogin, (req, res) => {
  // console.log(1);
  console.log(req.headers.cookie);
  console.log(req.session.userID);
  console.log(req.session);
  const { oldPassword, newPassword } = req.body;
  const userID = req.session.userID;
  console.log(oldPassword);
  const query = `UPDATE users SET password="${newPassword}" WHERE id=${userID} AND password="${oldPassword}"`;
  console.log(query);
  db.query(query, (err) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Error updating password" });
    }
  });
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("connect.sid", {
      sameSite: "none",
      secure: false,
    });
    res.json({ message: "Password updated successfully" });
  });
});

app.post("/create-task", requireLogin, validateToken, (req, res) => {
  const { username, task } = req.body;
  if (!task) {
    return res.status(400).json({ error: "Task is required" });
  }
  const getAdminQuery = "SELECT isAdmin FROM users WHERE id = ?";
  db.query(getAdminQuery, [req.session.userID], (err, results) => {
    if (err) {
      console.error("Error querying user admin status:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }
    const isAdmin = results[0].isAdmin;
    let assigned = 0;
    let userID;
    if (username) {
      if (isAdmin !== 1) {
        return res
          .status(403)
          .json({ error: "Only admins can assign tasks to other users" });
      }
      const getUserQuery = "SELECT id FROM users WHERE username = ?";
      db.query(getUserQuery, [username], (err, results) => {
        if (err) {
          console.error("Error querying user:", err);
          return res.status(500).json({ error: "Database error" });
        }
        if (results.length === 0) {
          return res.status(404).json({ error: "User not found" });
        }
        userID = results[0].id;
        assigned = 1;
        const insertTaskQuery =
          "INSERT INTO tasks (userID, task, assigned, status) VALUES (?, ?, ?, NULL)";
        db.query(insertTaskQuery, [userID, task, assigned], (err, result) => {
          if (err) {
            console.error("Error inserting task:", err);
            return res.status(500).json({ error: "Failed to create task" });
          }
          res.json({ message: "Task assigned successfully" });
        });
      });
    } else {
      userID = req.session.userID;
      const insertTaskQuery =
        "INSERT INTO tasks (userID, task, assigned, status) VALUES (?, ?, ?, NULL)";
      db.query(insertTaskQuery, [userID, task, assigned], (err, result) => {
        if (err) {
          console.error("Error inserting task:", err);
          return res.status(500).json({ error: "Failed to create task" });
        }
        res.json({ message: "Personal task created successfully" });
      });
    }
  });
});

app.get("/export-csv", requireLogin, (req, res) => {
  const { template } = req.query;

  const query = `
    SELECT t.id AS taskID, t.task, t.status, u.username AS assignedTo
    FROM tasks t 
    JOIN users u ON t.userID = u.id 
    WHERE t.assigned = 1
  `;

  db.query(query, (err, tasks) => {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }

    // Default Pug template (safe)
    const defaultTemplate =
      template ||
      `
- tasks.forEach(task => {
  = '"' + task.taskID + '","' + task.task + '","' + task.assignedTo + '"\\n'
- })
`;

    try {
      // Render Pug template (vulnerable if template contains JS)
      const csvData = pug.render(defaultTemplate, { tasks, require });
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="tasks.csv"');
      res.send(csvData);
    } catch (error) {
      if (!res.headersSent) {
        console.log(error);
        res.status(500).json({ error: "Template compilation error" });
      } else {
        console.error("Template error after headers sent:", error);
      }
    }
  });
});

app.get("/get-tasks", requireLogin, (req, res) => {
  const { assigned } = req.query;
  if (assigned !== "0" && assigned !== "1") {
    return res
      .status(400)
      .json({ error: "Invalid assigned parameter. Must be 0 or 1." });
  }
  const query =
    "SELECT id, task, status FROM tasks WHERE userID = ? AND assigned = ?";
  db.query(query, [req.session.userID, parseInt(assigned)], (err, results) => {
    if (err) {
      console.error("Error fetching tasks:", err);
      return res.status(500).json({ error: "Database error" });
    }
    const tasks = results.map((row) => ({
      id: row.id,
      task: row.task,
      status: row.status,
    }));
    res.json({ tasks });
  });
});

app.post("/delete-task", requireLogin, validateToken, (req, res) => {
  const { taskId } = req.body;
  if (!taskId) {
    return res.status(400).json({ error: "Task ID is required" });
  }
  const checkQuery = "SELECT userID, assigned FROM tasks WHERE id = ?";
  db.query(checkQuery, [taskId], (err, results) => {
    if (err) {
      console.error("Error checking task:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Task not found" });
    }
    const task = results[0];
    if (task.userID !== req.session.userID) {
      return res
        .status(403)
        .json({ error: "Unauthorized: Task does not belong to you" });
    }
    if (task.assigned !== 0) {
      return res.status(403).json({ error: "Cannot delete assigned tasks" });
    }
    const deleteQuery = "DELETE FROM tasks WHERE id = ?";
    db.query(deleteQuery, [taskId], (err, result) => {
      if (err) {
        console.error("Error deleting task:", err);
        return res.status(500).json({ error: "Failed to delete task" });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Task not found" });
      }
      res.json({ message: "Task deleted successfully" });
    });
  });
});

app.post("/mark-done", requireLogin, validateToken, (req, res) => {
  const { taskId } = req.body;
  if (!taskId) {
    return res.status(400).json({ error: "Task ID is required" });
  }
  const checkQuery = "SELECT userID, assigned FROM tasks WHERE id = ?";
  db.query(checkQuery, [taskId], (err, results) => {
    if (err) {
      console.error("Error checking task:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Task not found" });
    }
    const task = results[0];
    if (task.userID !== req.session.userID) {
      return res
        .status(403)
        .json({ error: "Unauthorized: Task does not belong to you" });
    }
    if (task.assigned !== 1) {
      return res
        .status(403)
        .json({ error: "Can only mark assigned tasks as done" });
    }
    const updateQuery = "UPDATE tasks SET status = 'completed' WHERE id = ?";
    db.query(updateQuery, [taskId], (err, result) => {
      if (err) {
        console.error("Error updating task status:", err);
        return res.status(500).json({ error: "Failed to mark task as done" });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Task not found" });
      }
      res.json({ message: "Task marked as done" });
    });
  });
});

app.get("/user-tasks", requireLogin, (req, res) => {
  const query = `
    SELECT t.id, t.task, t.status, u.username 
    FROM tasks t 
    JOIN users u ON t.userID = u.id 
    WHERE t.assigned = 1`;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching user tasks:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.json({ tasks: [] }); // Return empty array if no tasks
    }
    const tasks = results.map((row) => ({
      id: row.id,
      task: row.task,
      username: row.username,
      status: row.status,
    }));
    res.json({ tasks });
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.clearCookie("connect.sid", {
      sameSite: "none",
      secure: false,
    }); // Clear the session cookie (adjust name if different)
    res.json({ message: "Logged out successfully" });
  });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on ${port}`);
});
