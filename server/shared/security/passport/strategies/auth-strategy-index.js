// server/shared/security/passport/strategies/auth-strategy-index.js
/**
 * @file Authentication Strategies Index
 * @description Production-grade authentication strategies manager with enhanced security and organization context
 * @version 4.0.0
 */

const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('./local-strategy');
const GoogleStrategy = require('./google-strategy');
const GitHubStrategy = require('./github-strategy');
const LinkedInStrategy = require('./linkedin-strategy');
const OrganizationStrategy = require('./organization-strategy');
const PasskeyStrategy = require('./passkey-strategy');

const User = require('../../../users/models/user-model');
const Organization = require('../../../organizations/models/organization-model');
const TokenService = require('../../../auth/services/token-service');
const TokenBlacklistService = require('../../services/token-blacklist-service');
const AuditService = require('../../services/audit-service');
const logger = require('../../../utils/logger');
const config = require('../../../config');
const { AuthenticationError } = require('../../../utils/app-error');

/**
 * Enhanced Authentication Strategies Manager
 * @class AuthStrategiesManager
 */
class AuthStrategiesManager {
  constructor() {
    this.strategies = new Map();
    this.initialized = false;
    this.jwtOptions = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        ExtractJwt.fromUrlQueryParameter('token'),
        this.extractJwtFromCookie
      ]),
      secretOrKey: config.auth.jwtSecret || config.auth.accessToken.secret,
      issuer: config.auth.jwt?.issuer,
      audience: config.auth.jwt?.audience,
      algorithms: ['HS256'],
      passReqToCallback: true
    };
  }

  /**
   * Initialize all authentication strategies
   * @param {Object} app - Express application
   * @param {Object} options - Configuration options
   */
  async initialize(app, options = {}) {
    if (this.initialized) {
      logger.warn('Authentication strategies already initialized');
      return;
    }

    try {
      // Initialize passport
      app.use(passport.initialize());
      
      // Configure session if enabled
      if (options.enableSessions !== false && config.auth.sessionSecret) {
        app.use(passport.session());
        this.configureSessionSerialization();
      }

      // Configure all strategies
      await this.configureStrategies();

      // Add global middleware
      this.setupGlobalMiddleware(app);

      // Setup monitoring and health checks
      this.setupMonitoring();

      this.initialized = true;
      logger.info('Authentication strategies initialized successfully', {
        strategies: Array.from(this.strategies.keys()),
        sessionsEnabled: options.enableSessions !== false
      });
    } catch (error) {
      logger.error('Failed to initialize authentication strategies', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure all authentication strategies
   */
  async configureStrategies() {
    // JWT Strategy (Primary token-based auth)
    await this.configureJwtStrategy();

    // Local Strategy (Email/Password)
    await this.configureStrategy('local', LocalStrategy);

    // OAuth Strategies
    await this.configureStrategy('google', GoogleStrategy);
    await this.configureStrategy('github', GitHubStrategy);
    await this.configureStrategy('linkedin', LinkedInStrategy);

    // Organization Strategy (Multi-tenant SSO)
    await this.configureStrategy('organization', OrganizationStrategy);

    // Passkey Strategy (WebAuthn)
    await this.configureStrategy('passkey', PasskeyStrategy);
  }

  /**
   * Configure JWT strategy with enhanced validation
   */
  async configureJwtStrategy() {
    const strategy = new JwtStrategy(this.jwtOptions, async (req, payload, done) => {
      try {
        // Extract token for blacklist check
        const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

        // Check token blacklist
        const isBlacklisted = await TokenBlacklistService.isBlacklisted(token);
        if (isBlacklisted) {
          return done(new AuthenticationError('Token has been revoked'), false);
        }

        // Validate token type
        if (payload.type !== 'access') {
          return done(new AuthenticationError('Invalid token type'), false);
        }

        // Load user with organization context
        const user = await User.findById(payload.userId)
          .select('+active +security.lockoutUntil')
          .populate({
            path: 'organization.current',
            select: 'name slug type subscription settings active',
            model: 'Organization'
          })
          .lean();

        if (!user) {
          return done(new AuthenticationError('User not found'), false);
        }

        // Security checks
        if (!user.active) {
          return done(new AuthenticationError('Account is inactive'), false);
        }

        if (user.security?.lockoutUntil && user.security.lockoutUntil > new Date()) {
          return done(new AuthenticationError('Account is locked'), false);
        }

        // Check organization if required
        if (payload.organizationId && user.organization?.current) {
          if (user.organization.current._id.toString() !== payload.organizationId) {
            logger.warn('Organization context mismatch', {
              userId: user._id,
              tokenOrgId: payload.organizationId,
              userOrgId: user.organization.current._id
            });
          }
        }

        // Attach additional context
        user.tokenData = {
          jti: payload.jti,
          sessionId: payload.sessionId,
          deviceId: payload.deviceId
        };

        // Set organization permissions
        if (user.organization?.current) {
          user.currentOrganization = user.organization.current;
          user.organizationRole = user.organization.role;
          user.organizationPermissions = await this.getOrganizationPermissions(
            user._id,
            user.organization.current._id
          );
        }

        return done(null, user);
      } catch (error) {
        logger.error('JWT strategy error', {
          error: error.message,
          payload: { userId: payload.userId }
        });
        return done(error, false);
      }
    });

    passport.use('jwt', strategy);
    this.strategies.set('jwt', { strategy, type: 'token' });
    logger.info('JWT authentication strategy configured');
  }

  /**
   * Configure individual strategy
   */
  async configureStrategy(name, StrategyClass) {
    try {
      const strategyInstance = new StrategyClass();
      const strategy = await strategyInstance.createStrategy();
      
      if (strategy) {
        passport.use(name, strategy);
        this.strategies.set(name, {
          strategy,
          instance: strategyInstance,
          type: this.getStrategyType(name)
        });
        logger.info(`${name} authentication strategy configured`);
      }
    } catch (error) {
      logger.error(`Failed to configure ${name} strategy`, {
        error: error.message
      });
    }
  }

  /**
   * Configure session serialization
   */
  configureSessionSerialization() {
    passport.serializeUser((user, done) => {
      const sessionData = {
        id: user._id || user.id,
        organizationId: user.currentOrganization?._id
      };
      done(null, sessionData);
    });

    passport.deserializeUser(async (sessionData, done) => {
      try {
        const user = await User.findById(sessionData.id)
          .select('_id email role active firstName lastName organization')
          .populate('organization.current', 'name slug type')
          .lean();
        
        if (user && user.active) {
          user.id = user._id;
          done(null, user);
        } else {
          done(null, false);
        }
      } catch (error) {
        logger.error('Session deserialization error', { error });
        done(error, null);
      }
    });
  }

  /**
   * Create authentication middleware with enhanced features
   */
  authenticate(strategies, options = {}) {
    const strategyArray = Array.isArray(strategies) ? strategies : [strategies];
    
    return async (req, res, next) => {
      // Add request context
      req.authContext = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        origin: req.get('origin'),
        timestamp: new Date()
      };

      // Try strategies in order
      const tryStrategy = (index = 0) => {
        if (index >= strategyArray.length) {
          return this.handleAuthFailure(req, res, options);
        }

        const strategyName = strategyArray[index];
        const strategyConfig = this.strategies.get(strategyName);

        if (!strategyConfig) {
          logger.error(`Strategy ${strategyName} not configured`);
          return tryStrategy(index + 1);
        }

        passport.authenticate(strategyName, options, async (err, user, info) => {
          if (err) {
            logger.error(`Authentication error with ${strategyName}`, {
              error: err.message,
              context: req.authContext
            });
            return next(err);
          }

          if (!user) {
            // Log failure and try next strategy
            await this.logAuthAttempt(req, strategyName, false, info);
            return tryStrategy(index + 1);
          }

          // Authentication successful
          req.logIn(user, { session: options.session !== false }, async (loginErr) => {
            if (loginErr) {
              logger.error('Login error', {
                strategy: strategyName,
                error: loginErr.message
              });
              return next(loginErr);
            }

            // Set user context
            await this.setUserContext(req, user);

            // Log successful authentication
            await this.logAuthAttempt(req, strategyName, true);

            // Execute success callback
            if (options.successCallback) {
              options.successCallback(req, res, next);
            } else {
              next();
            }
          });
        })(req, res, next);
      };

      tryStrategy();
    };
  }

  /**
   * OAuth callback handler with enhanced security
   */
  oauthCallback(provider, options = {}) {
    return async (req, res, next) => {
      passport.authenticate(provider, async (err, user, info) => {
        if (err || !user) {
          return this.handleOAuthError(req, res, provider, err || info);
        }

        try {
          // Generate tokens with organization context
          const TokenRefreshService = require('../services/token-refresh-service');
          const tokens = await TokenRefreshService.generateTokensWithContext(user, {
            deviceInfo: {
              userAgent: req.get('user-agent'),
              ipAddress: req.ip,
              provider
            }
          });

          // Log OAuth success
          await AuditService.log({
            type: 'oauth_login',
            action: 'authenticate',
            category: 'authentication',
            result: 'success',
            userId: user._id,
            metadata: {
              provider,
              organizationId: user.currentOrganization?._id
            }
          });

          // Redirect with tokens
          const successUrl = this.buildOAuthSuccessUrl(tokens, options.successRedirect);
          res.redirect(successUrl);
        } catch (tokenError) {
          logger.error('OAuth token generation error', {
            provider,
            userId: user._id,
            error: tokenError.message
          });
          return this.handleOAuthError(req, res, provider, tokenError);
        }
      })(req, res, next);
    };
  }

  /**
   * Multi-strategy authentication middleware
   */
  multiStrategyAuth(options = {}) {
    const {
      strategies = ['jwt'],
      requireAuth = true,
      requireOrganization = false,
      allowedRoles = [],
      allowedPermissions = []
    } = options;

    return async (req, res, next) => {
      // Determine strategy based on request
      const strategy = this.determineStrategy(req);

      if (!strategy && requireAuth) {
        return res.status(401).json({
          success: false,
          error: {
            message: 'Authentication required',
            code: 'AUTH_REQUIRED'
          }
        });
      }

      if (!strategy) {
        return next();
      }

      // Use the authentication middleware
      this.authenticate(strategy, {
        session: this.shouldUseSession(strategy),
        failureMessage: `${strategy} authentication failed`,
        successCallback: async (req, res, next) => {
          // Validate role if required
          if (allowedRoles.length > 0 && !this.hasRequiredRole(req.user, allowedRoles)) {
            return res.status(403).json({
              success: false,
              error: {
                message: 'Insufficient role privileges',
                code: 'ROLE_REQUIRED',
                required: allowedRoles
              }
            });
          }

          // Validate permissions if required
          if (allowedPermissions.length > 0 && !this.hasRequiredPermissions(req.user, allowedPermissions)) {
            return res.status(403).json({
              success: false,
              error: {
                message: 'Insufficient permissions',
                code: 'PERMISSION_REQUIRED',
                required: allowedPermissions
              }
            });
          }

          // Check organization requirement
          if (requireOrganization && !req.user.currentOrganization) {
            return res.status(403).json({
              success: false,
              error: {
                message: 'Organization membership required',
                code: 'ORG_REQUIRED'
              }
            });
          }

          next();
        }
      })(req, res, next);
    };
  }

  /**
   * Create organization context middleware
   */
  createOrganizationContextMiddleware() {
    return async (req, res, next) => {
      if (!req.user) {
        return next();
      }

      try {
        // Ensure organization context is loaded
        if (!req.user.currentOrganization && req.user.organization?.current) {
          const currentOrg = await Organization.findById(req.user.organization.current)
            .select('_id name slug type subscription settings active')
            .lean();

          if (currentOrg && currentOrg.active) {
            req.user.currentOrganization = currentOrg;
            req.userOrganization = currentOrg;
          }
        }

        // Add permission helpers
        req.hasPermission = (permission) => {
          return this.checkPermission(req.user, permission);
        };

        req.requirePermission = (permission) => {
          if (!req.hasPermission(permission)) {
            res.status(403).json({
              success: false,
              error: {
                message: 'Insufficient permissions',
                code: 'PERMISSION_DENIED',
                required: permission
              }
            });
            return false;
          }
          return true;
        };

        next();
      } catch (error) {
        logger.error('Organization context middleware error', {
          error: error.message,
          userId: req.user?._id
        });
        next(); // Continue without organization context
      }
    };
  }

  // Helper methods

  /**
   * Extract JWT from cookie
   */
  extractJwtFromCookie(req) {
    if (req && req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }
    return null;
  }

  /**
   * Determine authentication strategy from request
   */
  determineStrategy(req) {
    // JWT token in header or cookie
    if (req.headers.authorization?.startsWith('Bearer ') || req.cookies?.access_token) {
      return 'jwt';
    }

    // Organization SSO
    if (req.body?.organization && req.body?.ssoToken) {
      return 'organization';
    }

    // Passkey
    if (req.body?.credential && req.body?.type === 'webauthn') {
      return 'passkey';
    }

    // Local auth
    if (req.body?.email && req.body?.password) {
      return 'local';
    }

    // OAuth callback
    if (req.query?.code && req.query?.state) {
      // Determine provider from state or path
      const provider = req.path.match(/\/(google|github|linkedin)\//)?.[1];
      return provider;
    }

    return null;
  }

  /**
   * Get strategy type
   */
  getStrategyType(name) {
    const tokenStrategies = ['jwt', 'api-key'];
    const oauthStrategies = ['google', 'github', 'linkedin'];
    const sessionStrategies = ['local', 'organization', 'passkey'];

    if (tokenStrategies.includes(name)) return 'token';
    if (oauthStrategies.includes(name)) return 'oauth';
    if (sessionStrategies.includes(name)) return 'session';
    return 'unknown';
  }

  /**
   * Should use session for strategy
   */
  shouldUseSession(strategy) {
    const sessionStrategies = ['local', 'google', 'github', 'linkedin', 'passkey'];
    return sessionStrategies.includes(strategy);
  }

  /**
   * Set user context on request
   */
  async setUserContext(req, user) {
    req.user = user;
    req.userId = user._id || user.id;
    req.userRole = user.role?.primary || user.role;
    req.userOrganization = user.currentOrganization;
    req.organizationRole = user.organization?.role;
    req.organizationPermissions = user.organizationPermissions || [];

    // Set in response locals for views
    if (req.res) {
      req.res.locals.user = user;
      req.res.locals.isAuthenticated = true;
    }
  }

  /**
   * Get organization permissions
   */
  async getOrganizationPermissions(userId, organizationId) {
    try {
      // This would fetch from organization member model
      // For now, return role-based permissions
      const user = await User.findById(userId).select('organization').lean();
      const role = user?.organization?.role || 'member';
      
      const rolePermissions = {
        owner: ['*'],
        admin: ['users.manage', 'settings.manage', 'billing.manage'],
        manager: ['users.view', 'projects.manage', 'reports.view'],
        member: ['projects.view', 'profile.manage']
      };

      return rolePermissions[role] || [];
    } catch (error) {
      logger.error('Failed to get organization permissions', { error });
      return [];
    }
  }

  /**
   * Check user permission
   */
  checkPermission(user, permission) {
    if (!user || !permission) return false;

    // Super admin has all permissions
    if (user.role?.primary === 'super_admin') return true;

    // Check organization permissions
    if (user.organizationPermissions?.includes('*')) return true;
    if (user.organizationPermissions?.includes(permission)) return true;

    // Check user permissions
    if (user.permissions?.includes('*')) return true;
    if (user.permissions?.includes(permission)) return true;

    return false;
  }

  /**
   * Check required role
   */
  hasRequiredRole(user, allowedRoles) {
    if (!user || !allowedRoles.length) return true;

    const userRoles = [user.role?.primary, ...(user.role?.secondary || [])].filter(Boolean);
    return allowedRoles.some(role => userRoles.includes(role));
  }

  /**
   * Check required permissions
   */
  hasRequiredPermissions(user, requiredPermissions) {
    if (!user || !requiredPermissions.length) return true;
    return requiredPermissions.every(permission => this.checkPermission(user, permission));
  }

  /**
   * Log authentication attempt
   */
  async logAuthAttempt(req, strategy, success, info = {}) {
    try {
      await AuditService.log({
        type: success ? 'auth_success' : 'auth_failure',
        action: 'authenticate',
        category: 'authentication',
        result: success ? 'success' : 'failure',
        userId: req.user?._id,
        metadata: {
          strategy,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          ...info
        }
      });
    } catch (error) {
      logger.error('Failed to log auth attempt', { error });
    }
  }

  /**
   * Handle authentication failure
   */
  handleAuthFailure(req, res, options) {
    const message = options.failureMessage || 'Authentication failed';
    const code = options.failureCode || 'AUTH_FAILED';

    return res.status(401).json({
      success: false,
      error: {
        message,
        code
      }
    });
  }

  /**
   * Handle OAuth error
   */
  handleOAuthError(req, res, provider, error) {
    const message = error?.message || 'OAuth authentication failed';
    const errorUrl = `/auth/error?provider=${provider}&error=${encodeURIComponent(message)}`;
    return res.redirect(errorUrl);
  }

  /**
   * Build OAuth success URL
   */
  buildOAuthSuccessUrl(tokens, customRedirect) {
    const baseUrl = customRedirect || '/auth/success';
    const params = new URLSearchParams({
      token: tokens.accessToken,
      refresh: tokens.refreshToken,
      expires: tokens.accessTokenExpiry
    });

    if (tokens.organizationContext) {
      params.append('org', tokens.organizationContext.id);
      params.append('orgName', tokens.organizationContext.name);
    }

    return `${baseUrl}?${params.toString()}`;
  }

  /**
   * Setup global middleware
   */
  setupGlobalMiddleware(app) {
    // Add token blacklist check
    app.use(TokenBlacklistService.createMiddleware());

    // Add organization context
    app.use(this.createOrganizationContextMiddleware());

    // Add request ID for tracing
    app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
      next();
    });
  }

  /**
   * Setup monitoring and health checks
   */
  setupMonitoring() {
    // Monitor authentication failures
    setInterval(() => {
      const metrics = this.getMetrics();
      if (metrics.failureRate > 0.1) {
        logger.warn('High authentication failure rate detected', metrics);
      }
    }, 60000); // Check every minute
  }

  /**
   * Get authentication metrics
   */
  getMetrics() {
    // This would integrate with your metrics system
    return {
      totalAttempts: 0,
      successCount: 0,
      failureCount: 0,
      failureRate: 0,
      strategies: {}
    };
  }

  /**
   * Get configured strategies
   */
  getConfiguredStrategies() {
    return Array.from(this.strategies.keys());
  }

  /**
   * Check if strategy is configured
   */
  isStrategyConfigured(strategyName) {
    return this.strategies.has(strategyName);
  }
}

// Create and export singleton instance
module.exports = new AuthStrategiesManager();