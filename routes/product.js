const express = require('express');
const router = express.Router();
const {pool} = require('../dbConfig');

router.get('/', async (req, res, next) => {
    try {
      const result = await pool.query('SELECT * FROM products');
      res.json(result.rows);
    } catch (err) {
      next(err); // Pass the error to Express's error handler
    }
  });
  
  router.get('/:id', async (req, res, next) => {
    try {
      const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Product not found' });
      }
      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  });

    module.exports = router;