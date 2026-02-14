const jwt = require('jsonwebtoken');
const User = require('../../models/userModel');
const ErrorHandler = require('../../utils/errorHandler');
const asyncErrorHandler = require('../helpers/asyncErrorHandler');
const TokenBlacklist = require('../../models/TokenBlacklist');

// SECURITY FIX: Enhanced authentication middleware with token revocation
exports.isAuthenticatedUser = asyncErrorHandler(async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return next(new ErrorHandler("Please Login to Access", 401));
    }

    try {
        // SECURITY FIX: Check if token is blacklisted
        const isBlacklisted = await TokenBlacklist.findOne({ token });
        if (isBlacklisted) {
            return next(new ErrorHandler("Token has been revoked", 401));
        }

        // Verify JWT token
        const decodedData = jwt.verify(token, process.env.JWT_SECRET);
        
        // SECURITY FIX: Check if user still exists
        const user = await User.findById(decodedData.id);
        if (!user) {
            return next(new ErrorHandler("User not found", 401));
        }

        // SECURITY FIX: Check if password was changed after token issuance
        if (user.passwordChangedAt && decodedData.iat < user.passwordChangedAt.getTime() / 1000) {
            return next(new ErrorHandler("Password recently changed. Please login again", 401));
        }

        // SECURITY FIX: Check if user account is active (add status field to user model)
        if (user.status === 'suspended' || user.status === 'banned') {
            return next(new ErrorHandler("Account is not active", 401));
        }

        req.user = user;
        req.tokenIssuedAt = decodedData.iat;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return next(new ErrorHandler("Invalid token", 401));
        }
        if (error.name === 'TokenExpiredError') {
            return next(new ErrorHandler("Token expired", 401));
        }
        return next(new ErrorHandler("Authentication failed", 401));
    }
});

// SECURITY FIX: Enhanced role authorization with additional checks
exports.authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return next(new ErrorHandler("User not authenticated", 401));
        }

        if (!roles.includes(req.user.role)) {
            return next(new ErrorHandler(`Role: ${req.user.role} is not allowed to access this resource`, 403));
        }

        // SECURITY FIX: Additional check for admin operations
        if (roles.includes('admin') && req.user.role === 'admin') {
            // Log admin actions for audit
            console.log(`Admin ${req.user._id} accessing ${req.method} ${req.originalUrl}`);
        }

        next();
    };
};

// SECURITY FIX: Middleware to check token freshness (for sensitive operations)
exports.requireFreshToken = (maxAgeMinutes = 15) => {
    return (req, res, next) => {
        if (!req.tokenIssuedAt) {
            return next(new ErrorHandler("Token information not available", 401));
        }

        const tokenAge = (Date.now() / 1000) - req.tokenIssuedAt;
        const maxAge = maxAgeMinutes * 60;

        if (tokenAge > maxAge) {
            return next(new ErrorHandler(`Token too old. Please re-authenticate for this sensitive operation. Max age: ${maxAgeMinutes} minutes`, 401));
        }

        next();
    };
};

// SECURITY FIX: Middleware to validate user ownership of resources
exports.validateResourceOwnership = (resourceIdParam = 'id', resourceModel = null) => {
    return asyncErrorHandler(async (req, res, next) => {
        const resourceId = req.params[resourceIdParam];
        const userId = req.user._id;

        if (resourceModel) {
            // Check if user owns the resource
            const resource = await resourceModel.findOne({ 
                _id: resourceId, 
                user: userId 
            });

            if (!resource) {
                return next(new ErrorHandler("Resource not found or access denied", 404));
            }
        }

        next();
    });
};

// SECURITY FIX: Rate limiting middleware for sensitive operations
const rateLimitStore = new Map();

exports.rateLimit = (maxRequests = 5, windowMs = 15 * 60 * 1000) => {
    return (req, res, next) => {
        const key = req.ip + ':' + req.originalUrl;
        const now = Date.now();
        const windowStart = now - windowMs;

        // Clean up old entries
        if (rateLimitStore.has(key)) {
            const requests = rateLimitStore.get(key).filter(timestamp => timestamp > windowStart);
            rateLimitStore.set(key, requests);
        }

        // Check current request count
        const requests = rateLimitStore.get(key) || [];
        
        if (requests.length >= maxRequests) {
            return next(new ErrorHandler("Too many requests. Please try again later.", 429));
        }

        // Add current request
        requests.push(now);
        rateLimitStore.set(key, requests);

        next();
    };
};
