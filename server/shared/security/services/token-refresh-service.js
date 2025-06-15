// server/shared/security/services/token-refresh-service.js
/**
 * @file Token Refresh Service
 * @description Handles token refresh operations with organization context and enhanced security
 * @version 3.0.0
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../../users/models/user-model');
const Organization = require('../../organizations/models/organization-model');
const TokenService = require('../../auth/services/token-service');
const TokenBlacklistService = require('./token-blacklist-service');
const AuditService = require('./audit-service');
const logger = require('../../utils/logger');
const config = require('../../config');
const { AuthenticationError, TokenError } = require('../../utils/app-error');

/**
 * Token Refresh Service Class
 * @class TokenRefreshService
 */
class TokenRefreshService {
  constructor() {
    this.accessTokenSecret = config.auth.jwtSecret || config.auth.accessToken.secret;
    this.refreshTokenSecret = config.auth.jwtRefreshSecret || config.auth.refreshToken.secret;
    this.accessTokenExpiry = config.auth.accessToken?.expiresIn || config.auth.accessTokenExpiry || '15m';
    this.refreshTokenExpiry = config.auth.refreshToken?.expiresIn || config.auth.refreshTokenExpiry || '7d';
    
    // Token rotation settings
    this.rotateRefreshTokens = config.auth.rotateRefreshTokens !== false;
    this.refreshTokenReuseWindow = config.auth.refreshTokenReuseWindow || 2000; // 2 seconds
    
    // Security settings
    this.maxRefreshChain = config.auth.maxRefreshChain || 10;
    this.refreshRateLimit = config.auth.refreshRateLimit || 10; // Max refreshes per minute
    
    // Token families for detecting token reuse attacks
    this.tokenFamilies = new Map();
  }

  /**
   * Generate tokens with organization context
   * @param {Object} user - User document
   * @param {Object} options - Token generation options
   * @returns {Promise<Object>} Generated tokens with metadata
   */
  async generateTokensWithContext(user, options = {}) {
    try {
      const {
        deviceInfo = {},
        rememberMe = false,
        includeRefreshToken = true
      } = options;

      // Ensure user has required fields populated
      if (!user.organization?.current && user.organization?.current) {
        user = await User.findById(user._id)
          .populate('organization.current', 'name slug type subscription settings active')
          .lean();
      }

      // Generate token family ID for refresh token chains
      const familyId = crypto.randomUUID();
      
      // Create token payloads
      const basePayload = this.createBasePayload(user);
      
      // Access token
      const accessTokenId = crypto.randomUUID();
      const accessPayload = {
        ...basePayload,
        type: 'access',
        jti: accessTokenId,
        deviceId: deviceInfo.deviceId,
        sessionId: crypto.randomUUID()
      };

      // Generate access token
      const accessToken = jwt.sign(
        accessPayload,
        this.accessTokenSecret,
        {
          expiresIn: this.accessTokenExpiry,
          issuer: config.auth.jwt?.issuer,
          audience: config.auth.jwt?.audience
        }
      );

      // Calculate expiry times
      const now = Date.now();
      const accessTokenExpiry = now + this.parseExpiry(this.accessTokenExpiry);
      
      const result = {
        accessToken,
        accessTokenExpiry,
        tokenType: 'Bearer',
        organizationContext: null
      };

      // Add organization context if available
      if (user.organization?.current) {
        result.organizationContext = {
          id: user.organization.current._id,
          name: user.organization.current.name,
          slug: user.organization.current.slug,
          type: user.organization.current.type,
          role: user.organization.role
        };
      }

      // Generate refresh token if requested
      if (includeRefreshToken) {
        const refreshTokenId = crypto.randomUUID();
        const refreshExpiry = rememberMe ? '30d' : this.refreshTokenExpiry;
        
        const refreshPayload = {
          userId: user._id.toString(),
          type: 'refresh',
          jti: refreshTokenId,
          familyId,
          chainIndex: 0,
          accessTokenId,
          deviceInfo
        };

        const refreshToken = jwt.sign(
          refreshPayload,
          this.refreshTokenSecret,
          {
            expiresIn: refreshExpiry,
            issuer: config.auth.jwt?.issuer
          }
        );

        // Store token family
        this.storeTokenFamily(familyId, {
          userId: user._id,
          deviceInfo,
          createdAt: new Date(),
          lastRefresh: new Date(),
          chainIndex: 0
        });

        result.refreshToken = refreshToken;
        result.refreshTokenExpiry = now + this.parseExpiry(refreshExpiry);
      }

      // Audit log
      await this.logTokenGeneration(user._id, {
        ...deviceInfo,
        organizationId: user.organization?.current?._id,
        tokenFamily: includeRefreshToken ? familyId : null
      });

      return result;
    } catch (error) {
      logger.error('Token generation error', {
        userId: user._id,
        error: error.message
      });
      throw new TokenError('Failed to generate tokens', 'TOKEN_GENERATION_FAILED');
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} options - Refresh options
   * @returns {Promise<Object>} New tokens
   */
  async refreshAccessToken(refreshToken, options = {}) {
    try {
      const {
        deviceInfo = {},
        rotateRefreshToken = this.rotateRefreshTokens
      } = options;

      // Check if refresh token is blacklisted
      const isBlacklisted = await TokenBlacklistService.isBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new AuthenticationError('Refresh token has been revoked', 'TOKEN_REVOKED');
      }

      // Verify refresh token
      let decoded;
      try {
        decoded = jwt.verify(refreshToken, this.refreshTokenSecret, {
          issuer: config.auth.jwt?.issuer,
          complete: true
        });
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          throw new TokenError('Refresh token has expired', 'REFRESH_TOKEN_EXPIRED');
        }
        throw new TokenError('Invalid refresh token', 'INVALID_REFRESH_TOKEN');
      }

      const payload = decoded.payload;

      // Validate token type
      if (payload.type !== 'refresh') {
        throw new TokenError('Invalid token type', 'INVALID_TOKEN_TYPE');
      }

      // Check token family for reuse attacks
      await this.checkTokenFamily(payload.familyId, payload.chainIndex);

      // Get user with fresh data
      const user = await User.findById(payload.userId)
        .select('+active +security.lockoutUntil')
        .populate('organization.current', 'name slug type subscription settings active')
        .lean();

      if (!user) {
        throw new AuthenticationError('User not found', 'USER_NOT_FOUND');
      }

      if (!user.active) {
        throw new AuthenticationError('User account is inactive', 'USER_INACTIVE');
      }

      if (user.security?.lockoutUntil && user.security.lockoutUntil > new Date()) {
        throw new AuthenticationError('Account is locked', 'ACCOUNT_LOCKED');
      }

      // Check if organization context has changed
      const organizationChanged = this.hasOrganizationChanged(
        payload.organizationId,
        user.organization?.current?._id
      );

      // Generate new access token
      const newTokens = await this.generateTokensWithContext(user, {
        deviceInfo: payload.deviceInfo || deviceInfo,
        includeRefreshToken: rotateRefreshToken
      });

      // Handle refresh token rotation
      if (rotateRefreshToken) {
        // Blacklist old refresh token
        await TokenBlacklistService.blacklistToken({
          token: refreshToken,
          tokenId: payload.jti,
          type: 'refresh',
          userId: user._id,
          reason: 'token_rotation',
          expiresAt: new Date(decoded.exp * 1000)
        });

        // Update token family
        this.updateTokenFamily(payload.familyId, {
          chainIndex: (payload.chainIndex || 0) + 1,
          lastRefresh: new Date()
        });
      }

      // Add metadata to response
      newTokens.organizationChanged = organizationChanged;
      
      // Audit log
      await this.logTokenRefresh(user._id, {
        ...deviceInfo,
        familyId: payload.familyId,
        chainIndex: payload.chainIndex,
        rotated: rotateRefreshToken,
        organizationChanged
      });

      return newTokens;
    } catch (error) {
      // Log security-relevant errors
      if (error.code === 'TOKEN_REUSE_DETECTED') {
        logger.error('Potential token reuse attack detected', {
          error: error.message,
          familyId: error.familyId
        });
      }

      throw error;
    }
  }

  /**
   * Create refresh middleware for automatic token refresh
   * @returns {Function} Express middleware
   */
  createRefreshMiddleware() {
    return async (req, res, next) => {
      // Skip if no user or not using JWT
      if (!req.user || !req.headers.authorization?.startsWith('Bearer ')) {
        return next();
      }

      try {
        const token = req.headers.authorization.substring(7);
        const decoded = jwt.decode(token);

        if (!decoded || !decoded.exp) {
          return next();
        }

        // Check if token is expiring soon (within 5 minutes)
        const expiresIn = decoded.exp * 1000 - Date.now();
        const shouldRefresh = expiresIn < 5 * 60 * 1000; // 5 minutes

        if (shouldRefresh) {
          req.shouldRefreshToken = true;
          
          // Add refresh hint to response
          res.setHeader('X-Token-Refresh-Required', 'true');
          res.setHeader('X-Token-Expires-In', Math.floor(expiresIn / 1000));
        }

        next();
      } catch (error) {
        // Silent fail - don't block request
        logger.debug('Refresh middleware error', { error: error.message });
        next();
      }
    };
  }

  /**
   * Revoke all tokens for a user
   * @param {string} userId - User ID
   * @param {Object} options - Revocation options
   * @returns {Promise<Object>} Revocation result
   */
  async revokeAllUserTokens(userId, options = {}) {
    const {
      reason = 'security_breach',
      excludeCurrentToken = false,
      currentTokenId = null
    } = options;

    try {
      // Blacklist all user tokens
      const blacklistedCount = await TokenBlacklistService.blacklistUserTokens(userId, {
        reason,
        excludeTokenIds: excludeCurrentToken && currentTokenId ? [currentTokenId] : []
      });

      // Clear token families for user
      this.clearUserTokenFamilies(userId);

      // Audit log
      await AuditService.log({
        type: 'tokens_revoked',
        action: 'revoke_all_tokens',
        category: 'security',
        result: 'success',
        userId,
        metadata: {
          reason,
          tokenCount: blacklistedCount,
          excludedCurrent: excludeCurrentToken
        }
      });

      return {
        success: true,
        revokedCount: blacklistedCount
      };
    } catch (error) {
      logger.error('Failed to revoke user tokens', {
        userId,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Validate token permissions for organization
   * @param {Object} tokenPayload - Decoded token payload
   * @param {string} requiredOrgId - Required organization ID
   * @returns {boolean} Is valid
   */
  validateOrganizationAccess(tokenPayload, requiredOrgId) {
    if (!requiredOrgId) return true;
    
    if (!tokenPayload.organizationId) {
      logger.warn('Token missing organization context', {
        userId: tokenPayload.userId
      });
      return false;
    }

    return tokenPayload.organizationId === requiredOrgId;
  }

  // Helper methods

  /**
   * Create base token payload
   */
  createBasePayload(user) {
    const payload = {
      userId: user._id.toString(),
      email: user.email,
      userType: user.userType,
      role: user.role?.primary || user.role,
      roles: this.getUserRoles(user),
      permissions: user.permissions || []
    };

    // Add organization context
    if (user.organization?.current) {
      payload.organizationId = user.organization.current._id.toString();
      payload.organizationType = user.organization.current.type;
      payload.organizationRole = user.organization.role;
    }

    return payload;
  }

  /**
   * Get all user roles
   */
  getUserRoles(user) {
    const roles = [];
    
    if (user.role?.primary) {
      roles.push(user.role.primary);
    } else if (user.role) {
      roles.push(user.role);
    }

    if (user.role?.secondary?.length) {
      roles.push(...user.role.secondary);
    }

    if (user.organization?.role) {
      roles.push(`org:${user.organization.role}`);
    }

    return [...new Set(roles)];
  }

  /**
   * Check if organization context has changed
   */
  hasOrganizationChanged(tokenOrgId, currentOrgId) {
    if (!tokenOrgId && !currentOrgId) return false;
    if (!tokenOrgId || !currentOrgId) return true;
    return tokenOrgId.toString() !== currentOrgId.toString();
  }

  /**
   * Parse expiry string to milliseconds
   */
  parseExpiry(expiry) {
    if (typeof expiry === 'number') return expiry;
    
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 900000; // Default 15 minutes

    const value = parseInt(match[1]);
    const unit = match[2];
    const units = {
      s: 1000,
      m: 60000,
      h: 3600000,
      d: 86400000
    };

    return value * units[unit];
  }

  /**
   * Store token family for tracking
   */
  storeTokenFamily(familyId, data) {
    // In production, this should use Redis or database
    this.tokenFamilies.set(familyId, {
      ...data,
      lastActivity: new Date()
    });

    // Clean old families periodically
    this.cleanTokenFamilies();
  }

  /**
   * Update token family
   */
  updateTokenFamily(familyId, updates) {
    const family = this.tokenFamilies.get(familyId);
    if (family) {
      this.tokenFamilies.set(familyId, {
        ...family,
        ...updates,
        lastActivity: new Date()
      });
    }
  }

  /**
   * Check token family for reuse attacks
   */
  async checkTokenFamily(familyId, expectedChainIndex) {
    const family = this.tokenFamilies.get(familyId);
    
    if (!family) {
      // New family or expired - allow
      return;
    }

    // Check for token reuse
    if (family.chainIndex > expectedChainIndex) {
      // Token reuse detected - revoke entire family
      await this.revokeTokenFamily(familyId);
      
      const error = new TokenError('Token reuse detected', 'TOKEN_REUSE_DETECTED');
      error.familyId = familyId;
      throw error;
    }

    // Check refresh chain length
    if (expectedChainIndex >= this.maxRefreshChain) {
      throw new TokenError('Maximum refresh chain length exceeded', 'MAX_REFRESH_CHAIN');
    }
  }

  /**
   * Revoke entire token family
   */
  async revokeTokenFamily(familyId) {
    const family = this.tokenFamilies.get(familyId);
    if (!family) return;

    // Blacklist all tokens for this user
    await TokenBlacklistService.blacklistUserTokens(family.userId, {
      reason: 'security_breach',
      metadata: { familyId, reason: 'token_reuse_detected' }
    });

    // Remove family
    this.tokenFamilies.delete(familyId);

    // Security alert
    logger.error('Token family revoked due to reuse', {
      familyId,
      userId: family.userId
    });
  }

  /**
   * Clear token families for user
   */
  clearUserTokenFamilies(userId) {
    for (const [familyId, family] of this.tokenFamilies.entries()) {
      if (family.userId.toString() === userId.toString()) {
        this.tokenFamilies.delete(familyId);
      }
    }
  }

  /**
   * Clean expired token families
   */
  cleanTokenFamilies() {
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    const now = Date.now();

    for (const [familyId, family] of this.tokenFamilies.entries()) {
      if (now - family.lastActivity.getTime() > maxAge) {
        this.tokenFamilies.delete(familyId);
      }
    }
  }

  /**
   * Log token generation
   */
  async logTokenGeneration(userId, metadata) {
    try {
      await AuditService.log({
        type: 'token_generated',
        action: 'generate_tokens',
        category: 'authentication',
        result: 'success',
        userId,
        metadata
      });
    } catch (error) {
      logger.error('Failed to log token generation', { error });
    }
  }

  /**
   * Log token refresh
   */
  async logTokenRefresh(userId, metadata) {
    try {
      await AuditService.log({
        type: 'token_refreshed',
        action: 'refresh_token',
        category: 'authentication',
        result: 'success',
        userId,
        metadata
      });
    } catch (error) {
      logger.error('Failed to log token refresh', { error });
    }
  }

  /**
   * Create rate limiter for token refresh
   */
  createRateLimiter() {
    // This would integrate with your rate limiting solution
    return async (req, res, next) => {
      // Implement rate limiting logic
      next();
    };
  }
}

// Create and export singleton instance
module.exports = new TokenRefreshService();