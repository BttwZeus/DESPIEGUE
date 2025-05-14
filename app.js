require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a la base de datos
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'suplements_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware de autenticación
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'miClaveSecreta123!', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware para admin
function isAdmin(req, res, next) {
  if (req.user.rol !== 'admin') return res.sendStatus(403);
  next();
}

// -------------------- ENDPOINTS --------------------

// Registro de usuario
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [userExists] = await pool.query('SELECT id FROM usuarios WHERE email = ?', [email]);

    if (userExists.length > 0) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (email, password_hash, rol) VALUES (?, ?, "cliente")',
      [email, hashedPassword]
    );

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);

    if (users.length === 0 || !(await bcrypt.compare(password, users[0].password_hash))) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = users[0];
    const token = jwt.sign(
      { id: user.id, email: user.email, rol: user.rol },
      process.env.JWT_SECRET || 'miClaveSecreta123!',
      { expiresIn: '24h' }
    );

    res.json({ token, rol: user.rol });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Obtener usuario autenticado
app.get('/api/user', authenticateToken, async (req, res) => {
  res.json(req.user);
});

// Obtener productos (público)
app.get('/api/productos', async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM productos');
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener productos' });
  }
});

// Admin: obtener productos
app.get('/api/admin/productos', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM productos');
    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener productos' });
  }
});

// Admin: crear producto
app.post('/api/admin/productos', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre, descripcion, precio, stock, categoria, imagen } = req.body;

    if (!nombre || !precio || !stock) {
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }

    const [result] = await pool.query(
      `INSERT INTO productos 
       (nombre, descripcion, precio, stock, categoria, imagen) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [nombre, descripcion, precio, stock, categoria || null, imagen || null]
    );

    const [newProduct] = await pool.query('SELECT * FROM productos WHERE id = ?', [result.insertId]);

    res.status(201).json(newProduct[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear producto' });
  }
});

// Añade estos endpoints después de los endpoints de admin

// Asegúrate de que tus endpoints del carrito coincidan con esto:

// Obtener carrito
app.get('/api/carrito', authenticateToken, async (req, res) => {
    try {
        const [cartItems] = await pool.query(`
            SELECT 
                c.id, 
                p.id as producto_id, 
                p.nombre, 
                CAST(p.precio AS DECIMAL(10,2)) as precio, 
                p.imagen, 
                c.cantidad
            FROM carrito c
            JOIN productos p ON c.producto_id = p.id
            WHERE c.usuario_id = ?
        `, [req.user.id]);
        
        res.json(cartItems);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener el carrito' });
    }
});

// Añadir al carrito
app.post('/api/carrito', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;
        
        // Verificar si el producto existe
        const [product] = await pool.query('SELECT id FROM productos WHERE id = ?', [productId]);
        if (product.length === 0) {
            return res.status(404).json({ error: 'Producto no encontrado' });
        }

        // Verificar si ya está en el carrito
        const [existingItem] = await pool.query(
            'SELECT id, cantidad FROM carrito WHERE usuario_id = ? AND producto_id = ?',
            [req.user.id, productId]
        );
        
        if (existingItem.length > 0) {
            // Incrementar cantidad
            await pool.query(
                'UPDATE carrito SET cantidad = cantidad + 1 WHERE id = ?',
                [existingItem[0].id]
            );
        } else {
            // Añadir nuevo item
            await pool.query(
                'INSERT INTO carrito (usuario_id, producto_id, cantidad) VALUES (?, ?, 1)',
                [req.user.id, productId]
            );
        }
        
        res.status(201).json({ message: 'Producto añadido al carrito' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al añadir al carrito' });
    }
});

// Eliminar del carrito
app.delete('/api/carrito/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Verificar que el item pertenece al usuario
        const [item] = await pool.query(
            'SELECT id FROM carrito WHERE id = ? AND usuario_id = ?',
            [id, req.user.id]
        );
        
        if (item.length === 0) {
            return res.status(404).json({ error: 'Item no encontrado en tu carrito' });
        }

        await pool.query('DELETE FROM carrito WHERE id = ?', [id]);
        res.json({ message: 'Item eliminado del carrito' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al eliminar del carrito' });
    }
});

app.put('/api/carrito/:id', authenticateToken, async (req, res) => {
  try {
    const { cantidad } = req.body;
    await pool.query(
      'UPDATE carrito SET cantidad = ? WHERE id = ? AND usuario_id = ?',
      [cantidad, req.params.id, req.user.id]
    );
    res.json({ message: 'Cantidad actualizada' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar cantidad' });
  }
});
// -------------------- FIN DE ENDPOINTS --------------------

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

// Manejo global de errores no capturados
process.on('unhandledRejection', (err) => {
  console.error('Error no manejado:', err);
});
