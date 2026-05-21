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
// const nodemailer = require("nodemailer");
const pug = require("pug");
const port = process.env.PORT;

function getNonLoopbackIP() {
  const nets = os.networkInterfaces();

  for (const [iface, addresses] of Object.entries(nets)) {
    // Skip loopback (lo)
    if (iface === "lo") continue;

    // Found the only other interface - return its IPv4
    for (const addr of addresses) {
      if (addr.family === "IPv4" && !addr.internal) {
        console.log(`Using ${iface}: ${addr.address}`);
        return addr.address;
      }
    }
  }

  throw new Error("No non-loopback IPv4 interface found");
}

// Usage
const HOST = getNonLoopbackIP();

app.use(
  cors({
    origin: ["http://" + HOST, "http://127.0.0.1"],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "x-csrf-token"],
    credentials: true,
  }),
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
  }),
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

// CSRF Token Endpoint
app.get("/api/csrf-token", (req, res) => {
  console.log("CGDDFDSHJS", req.session.csrfToken);
  if (!req.session.csrfToken) {
    console.log("No CSRF token in session");
    return res.status(401).json({ error: "No active session or CSRF token" });
  }
  res.json({ csrfToken: req.session.csrfToken });
});

// Routes
app.post("/api/register", (req, res) => {
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

app.post("/api/login", (req, res) => {
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

app.get("/api/me", requireLogin, (req, res) => {
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
    },
  );
});

app.get("/api/adminMe", requireLogin, (req, res) => {
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
    },
  );
});

// app.post("/api/change-password", requireLogin, (req, res) => {
//   // console.log(1);
//   console.log(req.headers.cookie);
//   console.log(req.session.userID);
//   console.log(req.session);
//   const { oldPassword, newPassword } = req.body;
//   const userID = req.session.userID;
//   console.log(oldPassword);
//   const query = `UPDATE users SET password="${newPassword}" WHERE id=${userID} AND password="${oldPassword}"`;
//   console.log(query);
//   db.query(query, (err) => {
//     if (err) {
//       console.error("SQL Error:", err);
//       return res.status(500).json({ error: "Error updating password" });
//     }
//   });
//   req.session.destroy((err) => {
//     if (err) {
//       console.error("Session destruction error:", err);
//       return res.status(500).json({ error: "Logout failed" });
//     }
//     res.clearCookie("connect.sid", {
//       sameSite: "none",
//       secure: false,
//     });
//     res.json({ message: "Password updated successfully" });
//   });
// });

// ============================================================
// FIXED /api/change-password endpoint
// ============================================================
//
// Problems fixed:
//
// 1. db.query() was fire-and-forget: session was destroyed even
//    if the UPDATE failed or hadn't finished yet.
//
// 2. res.clearCookie() was called with options that didn't match
//    how express-session originally SET the cookie, so the browser
//    silently ignored the clear instruction and the cookie stayed.
//    clearCookie() must be called with NO extra options (or options
//    that exactly mirror the Set-Cookie header used at login time)
//    so the browser's cookie-matching logic accepts the deletion.
//
// 3. res.clearCookie() was called BEFORE the response was sent in
//    some error branches, causing header conflicts.
// ============================================================

app.post("/api/change-password", requireLogin, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userID = req.session.userID;

  console.log("Cookie header  :", req.headers.cookie);
  console.log("Session userID :", userID);
  console.log("Session object :", req.session);
  console.log("Old password   :", oldPassword);
  const query = `UPDATE users SET password="${newPassword}" WHERE id=${userID} AND password="${oldPassword}"`;
  console.log("Query:", query);

  db.query(query, (err, result) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Error updating password" });
    }
    if (result.affectedRows === 0) {
      // Old password didn't match — don't touch the session
      return res.status(401).json({ error: "Incorrect current password" });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Session destruction error:", err);
        return res.status(500).json({ error: "Logout failed" });
      }
      res.clearCookie("connect.sid", { path: "/" });
      console.log("Session destroyed and cookie cleared successfully.");
      return res.json({ message: "Password updated successfully" });
    });
  });
});

app.post("/api/create-task", requireLogin, validateToken, (req, res) => {
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

app.get("/api/export-csv", requireLogin, (req, res) => {
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

app.get("/api/get-tasks", requireLogin, (req, res) => {
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

app.post("/api/delete-task", requireLogin, validateToken, (req, res) => {
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

app.post("/api/mark-done", requireLogin, validateToken, (req, res) => {
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

app.get("/api/user-tasks", requireLogin, (req, res) => {
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

app.post("/api/logout", (req, res) => {
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
