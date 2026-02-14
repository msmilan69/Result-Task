const mongoose = require('mongoose');

// SECURITY FIX: Token blacklist model for JWT revocation
const tokenBlacklistSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    expiresAt: {
        type: Date,
        required: true,
        index: true
    },
    reason: {
        type: String,
        enum: ['logout', 'password_change', 'admin_revocation', 'suspension'],
        default: 'logout'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// SECURITY FIX: Auto-delete expired tokens using MongoDB TTL index
tokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// SECURITY FIX: Compound index for efficient queries
tokenBlacklistSchema.index({ userId: 1, expiresAt: 1 });

// SECURITY FIX: Static method to blacklist all user tokens
tokenBlacklistSchema.statics.blacklistAllUserTokens = async function(userId, reason = 'logout') {
    const user = await mongoose.model('User').findById(userId);
    if (!user) {
        throw new Error('User not found');
    }

    // Create a special entry that will invalidate all tokens for this user
    // The auth middleware will check passwordChangedAt timestamp
    user.passwordChangedAt = new Date();
    await user.save({ validateBeforeSave: false });

    // Create blacklist entry for tracking
    return this.create({
        token: `ALL_TOKENS_USER_${userId}_${Date.now()}`,
        userId,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        reason
    });
};

// SECURITY FIX: Static method to check if user has any blacklisted tokens
tokenBlacklistSchema.statics.hasBlacklistedTokens = async function(userId) {
    const count = await this.countDocuments({
        userId,
        expiresAt: { $gt: new Date() }
    });
    return count > 0;
};

// SECURITY FIX: Static method to cleanup expired tokens (manual cleanup)
tokenBlacklistSchema.statics.cleanupExpired = async function() {
    const result = await this.deleteMany({
        expiresAt: { $lt: new Date() }
    });
    console.log(`Cleaned up ${result.deletedCount} expired blacklist entries`);
    return result.deletedCount;
};

module.exports = mongoose.model('TokenBlacklist', tokenBlacklistSchema);
