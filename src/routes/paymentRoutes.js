const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const stripeService = require('../services/stripeService');

router.use(protect);

router.post('/create-subscription', async (req, res) => {
  try {
    const { priceId } = req.body;
    const subscription = await stripeService.createSubscription(req.user, priceId);
    
    res.json({
      subscriptionId: subscription.id,
      clientSecret: subscription.latest_invoice.payment_intent.client_secret
    });
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ message: 'Error creating subscription' });
  }
});

router.post('/cancel-subscription', async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    await stripeService.cancelSubscription(subscriptionId);
    
    res.json({ message: 'Subscription cancelled successfully' });
  } catch (error) {
    console.error('Cancellation error:', error);
    res.status(500).json({ message: 'Error cancelling subscription' });
  }
});

module.exports = router;
