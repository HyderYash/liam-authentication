const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/User');

class StripeService {
  async createCustomer(user) {
    const customer = await stripe.customers.create({
      email: user.email,
      userId: user._id.toString()
      }
    );

    user.stripeCustomerId = customer.id;
    await user.save();
    return customer;
  }

  async createSubscription(user, priceId) {
    if (!user.stripeCustomerId) {
      await this.createCustomer(user);
    }

    const subscription = await stripe.subscriptions.create({
      customer: user.stripeCustomerId,
      items: [{ price: priceId }],
      payment_behavior: 'default_incomplete',
      expand: ['latest_invoice.payment_intent'],
    });

    return subscription;
  }

  async handleWebhook(event) {
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
        const subscription = event.data.object;
        const user = await User.findOne({
          stripeCustomerId: subscription.customer
        });

        if (user) {
          user.role = subscription.status === 'active' ? 'paying' : 'free';
          await user.save();
        }
        break;

      case 'customer.subscription.deleted':
        const canceledSubscription = event.data.object;
        const subscribedUser = await User.findOne({
          stripeCustomerId: canceledSubscription.customer
        });

        if (subscribedUser) {
          subscribedUser.role = 'free';
          await subscribedUser.save();
        }
        break;
    }
  }
}

module.exports = new StripeService();
