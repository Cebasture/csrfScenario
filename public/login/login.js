// document.getElementById('loginForm').addEventListener('submit', function(event) {
//   event.preventDefault();
//   const email = document.getElementById('email').value;
//   const password = document.getElementById('password').value;

//   fetch("http://127.0.0.1:3000/login", {
//     method: "POST",
//     credentials: "include",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({ email, password })
//   })
//   .then(res => res.json())

//   .then(data => {
//     if (data.message === 'Login successful') {
//       window.location.href = `../dashboard/${data.dashboard}`;
//     } else {
//       alert(data.error);
//     }
//   });
// })
// document.getElementById('loginForm').addEventListener('submit', function(event) {
//   event.preventDefault();
//   const email = document.getElementById('email').value;
//   const password = document.getElementById('password').value;

//   // First, fetch the CSRF token from the server
//   fetch("http://127.0.0.1:3000/csrf-token", {
//     method: "GET",
//   })
//   .then(res => {
//     if (!res.ok) {
//       throw new Error('Failed to fetch CSRF token');
//     }
//     return res.json();
//   })
//   .then(tokenData => {
//     const csrfToken = tokenData.csrfToken;

//     // Now, make the login request with the CSRF token in the header
//     return fetch("http://127.0.0.1:3000/login", {
//       method: "POST",
//       credentials: "include",
//       headers: { 
//         "Content-Type": "application/json",
//         "X-Csrf-Token": csrfToken  // Include the CSRF token
//       },
//       body: JSON.stringify({ email, password })
//     });
//   })
//   .then(res => res.json())
//   .then(data => {
//     if (data.message === 'Login successful') {
//       window.location.href = `../dashboard/${data.dashboard}`;
//     } else {
//       alert(data.error);
//     }
//   })
//   .catch(err => {
//     console.error('Error:', err);
//     alert('An error occurred. Please try again.');
//   });
// });

// let csrfToken;  // Global variable to store the CSRF token
// // Fetch CSRF token as soon as the page loads
// window.onload = function() {
//     fetch("http://127.0.0.1:3000/csrf-token", {
//         method: "GET",
//         credentials: "include"  // Include credentials to maintain session
//     })
//     .then(res => {
//         if (!res.ok) {
//             throw new Error('Failed to fetch CSRF token');
//         }
//         return res.json();
//     })
//     .then(tokenData => {
//         csrfToken = tokenData.csrfToken;  // Store the token globally
//         console.log('CSRF token fetched:', csrfToken);  // Optional: for debugging
//     })
//     .catch(err => {
//       console.error('Error fetching CSRF token:', err);
//       alert('Failed to load page security. Please refresh and try again.');
//   });
// };

document.getElementById('loginForm').addEventListener('submit', function(event) {
  
  // event.preventDefault();
  
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  console.log("before fetch")
  fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      credentials: "include",
      headers: { 
          "Content-Type": "application/json"
      },
      body: JSON.stringify({ email, password })
  })
  .then(res => res.json())
  .then(data => {
    // console.log(2);
    if (data.message === 'Login successful') {
    window.location.href = `../dashboard/${data.dashboard}`;
    } else {
        alert(data.error);
    }
  })
  .catch(err => {
      console.error('Error:', err);
      alert('An error occurred. Please try again.');
  });
});