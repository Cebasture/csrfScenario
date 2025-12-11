// let csrfToken;  // Global variable to store the CSRF token
// // Fetch CSRF token as soon as the page loads
// window.onload = function() {
//     fetch("http://127.0.0.1:3000/csrf-token", {
//         method: "GET"
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

document.getElementById('registerForm').addEventListener('submit', function(event) {
  event.preventDefault();

  const name = document.getElementById('name').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  if (password !== confirmPassword) {
    alert('Passwords do not match');
    return;
  }

  fetch(`${API_BASE_URL}/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username: name, password: password, email: email })
  })
  .then(response => response.json())
  .then(data => {
    if (data.message) {
      alert(data.message);   // "User registered successfully"
      window.location.href = '../../public/login/login.html';
    } else {
      alert(data.error);
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
});