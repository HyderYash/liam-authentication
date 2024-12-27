const rateLimit = require('express-rate-limit');
const Redis = require('redis');
const RedisStore = require('rate-limit-redis');

const redisClient = Redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

const createRateLimiter = (minutes, max) => {
  return rateLimit({
    store: new RedisStore({
      client: redisClient,
      prefix: 'rate-limit:'
    }),
    windowMs: minutes * 60 * 1000,
    max: max,
    message: {
      error: 'Too many requests, please try again later.'
    }
  });
};

exports.freeUserLimiter = createRateLimiter(10, 5);
exports.payingUserLimiter = createRateLimiter(10, 100);

exports.rateLimiterMiddleware = (req, res, next) => {
  if (req.user && req.user.role === 'paying') {
    return exports.payingUserLimiter(req, res, next);
  }
  return exports.freeUserLimiter(req, res, next);
};
