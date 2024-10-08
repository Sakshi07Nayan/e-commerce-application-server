const express = require('express');
const router = express.Router();
const { pool } = require('../dbConfig'); // PostgreSQL connection pool

// Route to get cart items by user ID
router.get('/cart/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const cartItems = await pool.query(
      `SELECT c.product_id, p.name, p.price, p.image_url, c.quantity
       FROM cart c
       JOIN products p ON c.product_id = p.id
       WHERE c.user_id = $1`,
      [userId]
    );

    if (cartItems.rows.length === 0) {
      return res.status(404).json({ message: "Cart is empty" });
    }

    res.json(cartItems.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Route to add a product to the cart
router.post('/cart/:userId/items', async (req, res) => {
  const { userId } = req.params;
  const { productId, quantity } = req.body;

  try {
    // Check if the product is already in the cart
    const existingItem = await pool.query(
      `SELECT * FROM cart WHERE user_id = $1 AND product_id = $2`,
      [userId, productId]
    );

    if (existingItem.rows.length > 0) {
      // Update the quantity if the product is already in the cart
      const updatedItem = await pool.query(
        `UPDATE cart SET quantity = quantity + $1 WHERE user_id = $2 AND product_id = $3 RETURNING *`,
        [quantity, userId, productId]
      );
      return res.json(updatedItem.rows[0]);
    } else {
      // Insert the product into the cart if it's not already there
      const newItem = await pool.query(
        `INSERT INTO cart (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING *`,
        [userId, productId, quantity]
      );
      res.status(201).json(newItem.rows[0]);
    }
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Route to remove a product from the cart
router.delete('/cart/:userId/items/:productId', async (req, res) => {
  const { userId, productId } = req.params;

  try {
    const deletedItem = await pool.query(
      `DELETE FROM cart WHERE user_id = $1 AND product_id = $2 RETURNING *`,
      [userId, productId]
    );

    if (deletedItem.rows.length === 0) {
      return res.status(404).json({ error: "Item not found in cart" });
    }

    res.json({ message: "Item removed from cart", item: deletedItem.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
