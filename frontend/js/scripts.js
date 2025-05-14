// Función para añadir al carrito (compartida entre páginas)
async function addToCart(productId) {
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  const response = await fetch('http://localhost:5000/api/carrito', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ productId })
  });

  if (response.ok) {
    updateCartCount();
  }
}

// Actualiza el contador del carrito
async function updateCartCount() {
  const token = localStorage.getItem('token');
  if (!token) return;

  const response = await fetch('http://localhost:5000/api/carrito', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const cartItems = await response.json();
  document.getElementById('cartCount').textContent = cartItems.length;
}

// Verifica autenticación al cargar páginas protegidas
function checkAuth() {
  const token = localStorage.getItem('token');
  if (!token && !window.location.pathname.includes('login.html') && !window.location.pathname.includes('register.html')) {
    window.location.href = 'login.html';
  }
}

// Ejecuta al cargar
document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  if (document.getElementById('cartCount')) updateCartCount();
});