// app.js - Comprehensive Node.js Express application with full observability

const express = require('express');
const promClient = require('prom-client');
const winston = require('winston');
const responseTime = require('response-time');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3001;

// ============= PROMETHEUS METRICS SETUP =============
const register = new promClient.Registry();

// Add default labels to all metrics
register.setDefaultLabels({
  app: 'nodejs-app',
  environment: process.env.NODE_ENV || 'development'
});

// Default metrics (CPU, memory, event loop lag, etc.)
promClient.collectDefaultMetrics({ 
  register,
  prefix: 'nodejs_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5]
});

// HTTP Request metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10],
  registers: [register]
});

const httpRequestTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const httpRequestSize = new promClient.Histogram({
  name: 'http_request_size_bytes',
  help: 'Size of HTTP requests in bytes',
  labelNames: ['method', 'route'],
  buckets: [100, 1000, 10000, 100000, 1000000],
  registers: [register]
});

const httpResponseSize = new promClient.Histogram({
  name: 'http_response_size_bytes',
  help: 'Size of HTTP responses in bytes',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [100, 1000, 10000, 100000, 1000000],
  registers: [register]
});

const activeConnections = new promClient.Gauge({
  name: 'active_connections',
  help: 'Number of active connections',
  registers: [register]
});

const totalErrors = new promClient.Counter({
  name: 'errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'route'],
  registers: [register]
});

// Business metrics
const userRegistrations = new promClient.Counter({
  name: 'user_registrations_total',
  help: 'Total number of user registrations',
  labelNames: ['status'],
  registers: [register]
});

const orderProcessed = new promClient.Counter({
  name: 'orders_processed_total',
  help: 'Total number of orders processed',
  labelNames: ['status', 'payment_method'],
  registers: [register]
});

const orderValue = new promClient.Histogram({
  name: 'order_value_dollars',
  help: 'Value of orders in dollars',
  labelNames: ['payment_method'],
  buckets: [10, 50, 100, 500, 1000, 5000],
  registers: [register]
});

const databaseQueryDuration = new promClient.Histogram({
  name: 'database_query_duration_seconds',
  help: 'Duration of database queries',
  labelNames: ['query_type', 'status'],
  buckets: [0.001, 0.01, 0.1, 0.5, 1, 2],
  registers: [register]
});

const cacheHits = new promClient.Counter({
  name: 'cache_hits_total',
  help: 'Total number of cache hits',
  labelNames: ['cache_name'],
  registers: [register]
});

const cacheMisses = new promClient.Counter({
  name: 'cache_misses_total',
  help: 'Total number of cache misses',
  labelNames: ['cache_name'],
  registers: [register]
});

// System metrics
const systemInfo = new promClient.Gauge({
  name: 'system_info',
  help: 'System information',
  labelNames: ['hostname', 'platform', 'arch', 'node_version'],
  registers: [register]
});

systemInfo.labels(
  os.hostname(),
  os.platform(),
  os.arch(),
  process.version
).set(1);

// ============= WINSTON LOGGING SETUP =============
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'nodejs-app',
    hostname: os.hostname(),
    pid: process.pid    
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
        })
      )
    }),
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 5
    })
  ]
});

// ============= MIDDLEWARE =============
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Response time middleware
app.use(responseTime((req, res, time) => {
  const route = req.route ? req.route.path : req.path;
  httpRequestDuration
    .labels(req.method, route, res.statusCode)
    .observe(time / 1000);
}));

// Request logging and metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  activeConnections.inc();

  // Log request
  logger.info('Incoming request', {
    method: req.method,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.get('user-agent')
  });

  // Track request size
  const requestSize = parseInt(req.get('content-length') || '0');
  const route = req.route ? req.route.path : req.path;
  if (requestSize > 0) {
    httpRequestSize.labels(req.method, route).observe(requestSize);
  }

  // Response finished handler
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    
    httpRequestTotal
      .labels(req.method, route, res.statusCode)
      .inc();
    
    activeConnections.dec();

    // Track response size
    const responseSize = parseInt(res.get('content-length') || '0');
    if (responseSize > 0) {
      httpResponseSize.labels(req.method, route, res.statusCode).observe(responseSize);
    }

    // Log response
    const logLevel = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    logger[logLevel]('Request completed', {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: duration,
      responseSize: responseSize
    });

    // Track errors
    if (res.statusCode >= 400) {
      totalErrors.labels(
        res.statusCode >= 500 ? 'server' : 'client',
        route
      ).inc();
    }
  });

  next();
});

// ============= HELPER FUNCTIONS =============

// Simulate database query
async function simulateDbQuery(queryType, shouldFail = false) {
  const start = Date.now();
  const delay = Math.random() * 500 + 50; // 50-550ms
  
  await new Promise(resolve => setTimeout(resolve, delay));
  
  const duration = (Date.now() - start) / 1000;
  const status = shouldFail ? 'error' : 'success';
  
  databaseQueryDuration
    .labels(queryType, status)
    .observe(duration);
  
  logger.debug('Database query executed', {
    queryType,
    status,
    duration
  });
  
  if (shouldFail) {
    throw new Error('Database query failed');
  }
  
  return { success: true, duration };
}

// Simulate cache lookup
function checkCache(cacheName, key) {
  const hit = Math.random() > 0.3; // 70% hit rate
  
  if (hit) {
    cacheHits.labels(cacheName).inc();
    logger.debug('Cache hit', { cacheName, key });
    return { hit: true, data: { cached: true, timestamp: new Date() } };
  } else {
    cacheMisses.labels(cacheName).inc();
    logger.debug('Cache miss', { cacheName, key });
    return { hit: false };
  }
}

// ============= ROUTES =============

// Health check
app.get('/health', (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage()
  };
  
  logger.info('Health check performed', healthCheck);
  res.json(healthCheck);
});

// Readiness check
app.get('/ready', (req, res) => {
  res.json({ 
    status: 'ready',
    timestamp: new Date().toISOString()
  });
});

// Metrics endpoint for Prometheus
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// GET /api/users - Get all users
app.get('/api/users', async (req, res) => {
  try {
    logger.info('Fetching users list');
    
    // Check cache first
    const cached = checkCache('users', 'all');
    if (cached.hit) {
      return res.json({
        source: 'cache',
        data: [
          { id: 1, name: 'John Doe', email: 'john@example.com', role: 'admin' },
          { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'user' },
          { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'user' }
        ]
      });
    }
    
    // Simulate database query
    await simulateDbQuery('select');
    
    res.json({
      source: 'database',
      data: [
        { id: 1, name: 'John Doe', email: 'john@example.com', role: 'admin' },
        { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'user' },
        { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'user' }
      ]
    });
  } catch (error) {
    logger.error('Error fetching users', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// POST /api/users - Create user
app.post('/api/users', async (req, res) => {
  try {
    const { name, email, role } = req.body;
    
    logger.info('Creating new user', { name, email, role });
    
    // Validate input
    if (!name || !email) {
      logger.warn('User creation failed - validation error', { name, email });
      userRegistrations.labels('validation_failed').inc();
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // Simulate database insert
    await simulateDbQuery('insert');
    
    const newUser = {
      id: Math.floor(Math.random() * 10000),
      name,
      email,
      role: role || 'user',
      createdAt: new Date().toISOString()
    };
    
    userRegistrations.labels('success').inc();
    logger.info('User created successfully', newUser);
    
    res.status(201).json({
      message: 'User created successfully',
      user: newUser
    });
  } catch (error) {
    userRegistrations.labels('error').inc();
    logger.error('Error creating user', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// POST /api/orders - Process order
app.post('/api/orders', async (req, res) => {
  try {
    const { userId, items, paymentMethod, totalAmount } = req.body;
    
    logger.info('Processing order', { userId, itemCount: items?.length, paymentMethod, totalAmount });
    
    // Validate
    if (!userId || !items || !totalAmount) {
      logger.warn('Order validation failed', { userId, items, totalAmount });
      orderProcessed.labels('validation_failed', paymentMethod || 'unknown').inc();
      return res.status(400).json({ error: 'Invalid order data' });
    }
    
    // Simulate payment processing
    await simulateDbQuery('insert');
    
    const orderId = `ORD-${Date.now()}`;
    
    orderProcessed.labels('success', paymentMethod).inc();
    orderValue.labels(paymentMethod).observe(totalAmount);
    
    logger.info('Order processed successfully', { orderId, userId, totalAmount, paymentMethod });
    
    res.status(201).json({
      message: 'Order processed successfully',
      orderId,
      status: 'confirmed',
      estimatedDelivery: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    });
  } catch (error) {
    orderProcessed.labels('error', req.body.paymentMethod || 'unknown').inc();
    logger.error('Error processing order', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Failed to process order' });
  }
});

// GET /api/products - Get products with caching
app.get('/api/products', async (req, res) => {
  try {
    const { category } = req.query;
    
    logger.info('Fetching products', { category });
    
    // Check cache
    const cached = checkCache('products', category || 'all');
    if (cached.hit) {
      return res.json({
        source: 'cache',
        products: [
          { id: 1, name: 'Product A', price: 29.99, category: 'electronics' },
          { id: 2, name: 'Product B', price: 49.99, category: 'electronics' },
          { id: 3, name: 'Product C', price: 19.99, category: 'books' }
        ]
      });
    }
    
    // Simulate database query
    await simulateDbQuery('select');
    
    res.json({
      source: 'database',
      products: [
        { id: 1, name: 'Product A', price: 29.99, category: 'electronics' },
        { id: 2, name: 'Product B', price: 49.99, category: 'electronics' },
        { id: 3, name: 'Product C', price: 19.99, category: 'books' }
      ]
    });
  } catch (error) {
    logger.error('Error fetching products', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// GET /api/slow - Simulate slow endpoint
app.get('/api/slow', async (req, res) => {
  const delay = parseInt(req.query.delay) || 3000;
  
  logger.warn('Slow endpoint called', { delay });
  
  await new Promise(resolve => setTimeout(resolve, delay));
  
  res.json({ 
    message: 'This was slow',
    delay: delay
  });
});

// GET /api/error - Simulate error
app.get('/api/error', (req, res) => {
  logger.error('Intentional error triggered', { 
    endpoint: '/api/error',
    query: req.query
  });
  
  totalErrors.labels('intentional', '/api/error').inc();
  
  throw new Error('This is an intentional error for testing');
});

// GET /api/random-error - Random errors for testing
app.get('/api/random-error', async (req, res) => {
  try {
    logger.info('Random error endpoint called');
    
    // 30% chance of error
    if (Math.random() < 0.3) {
      await simulateDbQuery('select', true);
    } else {
      await simulateDbQuery('select', false);
    }
    
    res.json({ 
      message: 'Success!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Random error occurred', { error: error.message });
    res.status(500).json({ error: 'Database error occurred' });
  }
});

// GET /api/stats - Application statistics
app.get('/api/stats', async (req, res) => {
  const metrics = await register.getMetricsAsJSON();
  
  res.json({
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    platform: {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version
    },
    metrics: metrics
  });
});

// POST /api/bulk-test - Generate load for testing
app.post('/api/bulk-test', async (req, res) => {
  const { count = 10 } = req.body;
  
  logger.info('Bulk test started', { count });
  
  const results = {
    successful: 0,
    failed: 0,
    totalDuration: 0
  };
  
  for (let i = 0; i < count; i++) {
    try {
      const start = Date.now();
      await simulateDbQuery('select', Math.random() < 0.1); // 10% failure rate
      results.successful++;
      results.totalDuration += Date.now() - start;
    } catch (error) {
      results.failed++;
    }
  }
  
  logger.info('Bulk test completed', results);
  
  res.json({
    message: 'Bulk test completed',
    ...results,
    averageDuration: results.totalDuration / count
  });
});

// 404 handler
app.use((req, res) => {
  logger.warn('Route not found', { 
    path: req.path,
    method: req.method
  });
  
  res.status(404).json({ 
    error: 'Route not found',
    path: req.path
  });
});

// Error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message, 
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  totalErrors.labels('unhandled', req.path).inc();
  
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============= GRACEFUL SHUTDOWN =============
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

// ============= START SERVER =============
const server = app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    platform: os.platform()
  });
  
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🚀 Node.js Observability App                               ║
║                                                               ║
║   Server:         http://localhost:${PORT}                         ║
║   Metrics:        http://localhost:${PORT}/metrics                 ║
║   Health:         http://localhost:${PORT}/health                  ║
║                                                               ║
║   📊 Endpoints:                                               ║
║   - GET  /api/users                                           ║
║   - POST /api/users                                           ║
║   - POST /api/orders                                          ║
║   - GET  /api/products                                        ║
║   - GET  /api/stats                                           ║
║   - GET  /api/slow                                            ║
║   - GET  /api/error                                           ║
║   - GET  /api/random-error                                    ║
║   - POST /api/bulk-test                                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});