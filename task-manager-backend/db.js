require("dotenv").config();
const os = require("os");
const mysql = require("mysql2");

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
// Create a connection to the database
const connection = mysql.createConnection({
  host: HOST,
  user: process.env.DB_USER,
  password: "johnPassword!@#$%",
  database: process.env.DB_NAME,
});

// Connect to the database
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err);
    return;
  }
  console.log("Connected to the MySQL database.");
});

const createTableQuery = `
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    isAdmin TINYINT(1) NOT NULL DEFAULT 0,
    resetToken VARCHAR(255),
    resetTokenExpiry DATETIME
);`;

const createTasksTableQuery = `
CREATE TABLE IF NOT EXISTS tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userID INT NOT NULL,
    task VARCHAR(255) NOT NULL,
    FOREIGN KEY (userID) REFERENCES users(id) ON DELETE CASCADE,
    assigned TINYINT(1) NOT NULL DEFAULT 0,
    status VARCHAR(255) NULL
);`;

connection.query(createTableQuery, (err) => {
  if (err) {
    console.error("Error creating users table:", err);
  } else {
    console.log("Users table ready!");
    // Create tasks table after users table
    connection.query(createTasksTableQuery, (err) => {
      if (err) {
        console.error("Error creating tasks table:", err);
      } else {
        console.log("Tasks table ready!");
      }
    });
  }
});

module.exports = connection;
