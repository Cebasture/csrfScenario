let csrfToken;  // Global variable to store the CSRF token
// Fetch CSRF token as soon as the page loads
window.onload = getCSRF();
window.onload = loadAssignedTasks();
window.onload = loadPersonalTasks

function getCSRF() {
    fetch(`${API_BASE_URL}/csrf-token`, {
        method: "GET",
        credentials: "include"  // Include credentials to maintain session
    })
    .then(res => {
        if (!res.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        return res.json();
    })
    .then(tokenData => {
        csrfToken = tokenData.csrfToken;  // Store the token globally
        console.log('CSRF token fetched:', csrfToken);  // Optional: for debugging
        // Optionally, load initial tasks after token is fetched
        loadPersonalTasks();  // Load personal tasks on page load
    })
    .catch(err => {
        console.error('Error fetching CSRF token:', err);
        alert('Failed to load page security. Please refresh and try again.');
    });
}
// ----------- Section Switching -----------
function showSection(section) {
    document.querySelectorAll('.section').forEach(sec => sec.classList.add('hidden'));
    document.getElementById(section).classList.remove('hidden');
    document.querySelectorAll('.sidebar li').forEach(li => li.classList.remove('active'));
    event.target.classList.add('active');
    // Load tasks when the section is shown
    if (section === 'todo') {
        loadPersonalTasks();
    } else if (section === 'assignedTasks') {
        loadAssignedTasks();
    }
}

// ----------- To-Do Logic (Front-end only demo) -----------
function addTask() {
    const input = document.getElementById('taskInput');
    const taskText = input.value.trim();
    if (taskText === "") return;

    const li = document.createElement("li");
    li.innerHTML = `
        <span onclick="this.classList.toggle('done')">${taskText}</span>
        <button class="delete" onclick="this.parentElement.remove()">X</button>
    `;

    document.getElementById("taskList").appendChild(li);
    input.value = "";
}

// ----------- Change Password (real backend needed) -----------
function changePassword() {
    const oldPass = document.getElementById("oldPassword").value;
    const newPass = document.getElementById("newPassword").value;

    fetch(`${API_BASE_URL}/change-password`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ oldPassword: oldPass, newPassword: newPass })
    })
    .then(res => res.json())
    .then(data => alert(data.message || data.error));
}

// ----------- Logout -----------
function logout() {
    fetch(`${API_BASE_URL}/logout`, {
        method: "POST",
        credentials: "include"
    })
    .then(() => {
        window.location.href = "../login/login.html";
    });
}

// ----------- Load Profile Data -----------
fetch(`${API_BASE_URL}/me`, { credentials: "include" })
.then(res => {
    if (res.status === 401) {
        // Redirect to normal dashboard if unauthorized
        window.location.href = "adminDashboard.html";
        return;
    }else if (res.status === 403) {
        window.location.href = "../login/login.html";
        return;
    }
    return res.json();
})
.then(user => {
    if (user) {
        document.getElementById('userEmail').textContent = user.email;
    }
})
.catch(err => console.error('Error:', err));

// ----------- Add Task Form Submission -----------
document.getElementById('addTaskForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent default form submission
    const taskText = document.getElementById('taskInput').value.trim();
    if (taskText === "") return;
    // Check if CSRF token is available
    if (!csrfToken) {
        alert('Security token not loaded. Please wait or refresh the page.');
        return;
    }
    // Make the create-task request with the pre-fetched CSRF token in the header
    fetch(`${API_BASE_URL}/create-task`, {
        method: "POST",
        credentials: "include",
        headers: { 
            "Content-Type": "application/json",
            "x-csrf-token": csrfToken  // Use the pre-fetched token
        },
        body: JSON.stringify({ task: taskText })
    })
    .then(res => res.json())
    .then(data => {
        if (data.message) {
            alert(data.message);
            getCSRF();
            document.getElementById('taskInput').value = ""; // Clear input on success
            loadPersonalTasks(); // Reload personal tasks
        } else {
            alert(data.error);
        }
    })
    .catch(err => {
        console.error('Error:', err);
        alert("Error: " + err.message);
    });
});
// document.getElementById('addTaskForm').addEventListener('submit', function(event) {
//     event.preventDefault(); // Prevent default form submission
//     const taskText = document.getElementById('taskInput').value.trim();
//     if (taskText === "") return;
//     // Send to server
//     fetch("http://127.0.0.1:3000/create-task", {
//         method: "POST",
//         credentials: "include",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ task: taskText })
//     })
//     .then(res => res.json())
//     .then(data => {
//         if (data.message) {
//             alert(data.message);
//             document.getElementById('taskInput').value = ""; // Clear input on success
//             // Optionally, reload the task list or add to UI
//             loadTasks(); // Assuming you have a function to load tasks
//         } else {
//             alert(data.error);
//         }
//     })
//     .catch(err => alert("Error: " + err.message));
// });

// ----------- Load Personal Tasks (assigned=0) -----------
// function loadPersonalTasks() {
//     fetch("http://127.0.0.1:3000/get-tasks?assigned=0", {
//         method: "GET",
//         credentials: "include"
//     })
//     .then(res => res.json())
//     .then(data => {
//         const taskList = document.getElementById('taskList');
//         taskList.innerHTML = ''; // Clear existing tasks
//         if (data.tasks && data.tasks.length > 0) {
//             data.tasks.forEach(task => {
//                 const li = document.createElement("li");
//                 li.innerHTML = `<span>${task}</span>`;
//                 taskList.appendChild(li);
//             });
//         } else {
//             taskList.innerHTML = '<li>No personal tasks.</li>';
//         }
//     })
//     .catch(err => {
//         console.error('Error loading personal tasks:', err);
//         document.getElementById('taskList').innerHTML = '<li>Error loading tasks.</li>';
//     });
// }
function loadPersonalTasks() {
    fetch(`${API_BASE_URL}/get-tasks?assigned=0`, {
        method: "GET",
        credentials: "include"
    })
    .then(res => res.json())
    .then(data => {
        const taskList = document.getElementById('taskList');
        taskList.innerHTML = ''; // Clear existing tasks
        if (data.tasks && data.tasks.length > 0) {
            data.tasks.forEach(task => {
                const li = document.createElement("li");
                li.innerHTML = `
                    <span>${task.task}</span>
                    <button class="delete" onclick="deleteTask(${task.id})">Delete</button>
                `;
                taskList.appendChild(li);
            });
        } else {
            taskList.innerHTML = '<li>No personal tasks.</li>';
        }
    })
    .catch(err => {
        console.error('Error loading personal tasks:', err);
        document.getElementById('taskList').innerHTML = '<li>Error loading tasks.</li>';
    });
}

// ----------- Delete Task -----------
function deleteTask(taskId) {
    if (!confirm("Are you sure you want to delete this task?")) return;
    // Check if CSRF token is available
    if (!csrfToken) {
        alert('Security token not loaded. Please wait or refresh the page.');
        return;
    }
    fetch(`${API_BASE_URL}/delete-task`, {
        method: "POST",
        credentials: "include",
        headers: { 
            "Content-Type": "application/json",
            "x-csrf-token": csrfToken  // Include the CSRF token
        },
        body: JSON.stringify({ taskId })  // Send taskId in the body
    })
    .then(res => res.json())
    .then(data => {
        getCSRF();
        if (data.message) {
            loadPersonalTasks(); // Reload personal tasks
        } else {
            alert(data.error);
        }
    })
    .catch(err => {
        console.error('Error deleting task:', err);
        alert("Error: " + err.message);
    });
}

// ----------- Load assigned Tasks (assigned=1) -----------
// function loadAssignedTasks() {
//     fetch("http://127.0.0.1:3000/get-tasks?assigned=1", {
//         method: "GET",
//         credentials: "include"
//     })
//     .then(res => res.json())
//     .then(data => {
//         const taskList = document.getElementById('assignedTaskList');
//         taskList.innerHTML = ''; // Clear existing tasks
//         if (data.tasks && data.tasks.length > 0) {
//             data.tasks.forEach(task => {
//                 const li = document.createElement("li");
//                 li.innerHTML = `<span>${task}</span>`;
//                 taskList.appendChild(li);
//             });
//         } else {
//             taskList.innerHTML = '<li>No assigned tasks.</li>';
//         }
//     })
//     .catch(err => {
//         console.error('Error loading assigned tasks:', err);
//         document.getElementById('assignedTaskList').innerHTML = '<li>Error loading tasks.</li>';
//     });
// }
function loadAssignedTasks() {
    fetch(`${API_BASE_URL}/get-tasks?assigned=1`, {
        method: "GET",
        credentials: "include"
    })
    .then(res => res.json())
    .then(data => {
        const taskList = document.getElementById('assignedTaskList');
        taskList.innerHTML = ''; // Clear existing tasks
        if (data.tasks && data.tasks.length > 0) {
            data.tasks.forEach(task => {
                const statusClass = task.status == "completed" ? 'status-completed' : 'status-pending';
                const statusText = task.status == "completed" ? 'Completed' : 'Pending';
                const buttonHtml = task.status == "completed" ? '' : `<button class="mark-done" onclick="markDone(${task.id})">Mark as Done</button>`;
                const li = document.createElement("li");
                li.innerHTML = `
                    <span>${task.task} - Status: <span class="${statusClass}">${statusText}</span></span>
                    ${buttonHtml}
                `;
                taskList.appendChild(li);
            });
        } else {
            taskList.innerHTML = '<li>No assigned tasks.</li>';
        }
    })
    .catch(err => {
        console.error('Error loading assigned tasks:', err);
        document.getElementById('assignedTaskList').innerHTML = '<li>Error loading tasks.</li>';
    });
}

// ----------- Mark Task as Done -----------
function markDone(taskId) {
    // Check if CSRF token is available
    if (!csrfToken) {
        alert('Security token not loaded. Please wait or refresh the page.');
        return;
    }
    fetch(`${API_BASE_URL}/mark-done`, {
        method: "POST",
        credentials: "include",
        headers: { 
            "Content-Type": "application/json",
            "x-csrf-token": csrfToken  // Include the CSRF token
        },
        body: JSON.stringify({ taskId })
    })
    .then(res => res.json())
    .then(data => {
        if (data.message) {
            loadAssignedTasks(); // Reload assigned tasks
        } else {
            alert(data.error);
        }
    })
    .catch(err => {
        console.error('Error marking task as done:', err);
        alert("Error: " + err.message);
    });
}