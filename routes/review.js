const express = require('express');
const router = express.Router();
const {pool} = require('../dbConfig');


router.get('/:id/reviews', async (req, res) => {
    const productId = parseInt(req.params.id); // Get product ID from the URL

    try {
        const result = await pool.query(
            `SELECT 
                r.rating,
                r.comment,
                u.name,
                r.created_at AS date 
            FROM 
                reviews r
            JOIN 
                users u ON r.user_id = u.id  
            WHERE 
                r.product_id = $1`, // Use parameterized query for security
            [productId]
        );

        if (result.rows.length > 0) {
            res.json(result.rows); // Send back the reviews
        } else {
            res.status(404).json({ message: 'No reviews found for this product.' }); // Handle case where no reviews exist
        }
    } catch (error) {
        console.error('Error fetching reviews:', error); // Log any errors
        res.status(500).json({ message: 'Internal server error' }); // Send error response
    }
});

module.exports = router;