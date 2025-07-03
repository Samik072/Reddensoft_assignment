document.getElementById('signupForm').addEventListener('submit', e => {
  const pwd = e.target.password.value;
  const rule = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{8,}$/;
  if (!rule.test(pwd)) {
    e.preventDefault();
    alert('Password must be ≥8 chars, include uppercase, lowercase, number & special character.');
  }
});
