document.getElementById('forgotPasswordForm').addEventListener('submit', function(event) {
  event.preventDefault();
  const email = document.getElementById('email').value;

  fetch('/forgot-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email })
  })
  .then(response => response.json())
  .then(data => {
    if (data.message) {
      alert(data.message);
    } else {
      alert(data.error);
    }
  })
  .catch(error => {
    console.error('Error:', error);
  });
});
