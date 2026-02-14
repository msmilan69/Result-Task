// ============================================
// CRITICAL FIX #3: SIWE Backend Verification
// ============================================
// File: backend/controllers/siweController.js

const { SiweMessage } = require('siwe');
const User = require('../models/userModel');
const sendToken = require('../utils/sendToken');
const asyncErrorHandler = require('../middlewares/helpers/asyncErrorHandler');
const ErrorHandler = require('../utils/errorHandler');

/**
 * Verify SIWE (Sign-In with Ethereum) signature and authenticate user
 * 
 * ✅ SECURITY FIX: Implements proper server-side signature verification
 */
exports.siweVerify = asyncErrorHandler(async (req, res, next) => {
    const { message, signature } = req.body;
    
    // Validate required fields
    if (!message || !signature) {
        return next(new ErrorHandler("Message and signature are required", 400));
    }
    
    // Validate message structure
    if (!message.domain || !message.address || !message.nonce || !message.chainId) {
        return next(new ErrorHandler("Invalid message structure", 400));
    }
    
    try {
        // ✅ Reconstruct the SIWE message
        const siweMessage = new SiweMessage(message);
        
        // ✅ Verify the signature cryptographically
        const fields = await siweMessage.verify({ signature });
        
        // ✅ Security Check 1: Verify message hasn't expired
        if (fields.data.expirationTime) {
            const expirationDate = new Date(fields.data.expirationTime);
            if (expirationDate < new Date()) {
                return next(new ErrorHandler("Signature has expired", 401));
            }
        }
        
        // ✅ Security Check 2: Verify domain matches
        const requestHost = req.get('host');
        if (fields.data.domain !== requestHost) {
            console.warn(`Domain mismatch: expected ${requestHost}, got ${fields.data.domain}`);
            return next(new ErrorHandler("Domain mismatch - possible phishing attempt", 401));
        }
        
        // ✅ Security Check 3: Verify URI matches
        const expectedUri = `${req.protocol}://${requestHost}`;
        if (fields.data.uri && !fields.data.uri.startsWith(expectedUri)) {
            return next(new ErrorHandler("URI mismatch", 401));
        }
        
        // ✅ Security Check 4: Verify nonce hasn't been used (prevent replay attacks)
        const nonceExists = await User.findOne({ 'siweNonces.nonce': fields.data.nonce });
        if (nonceExists) {
            return next(new ErrorHandler("Nonce has already been used - possible replay attack", 401));
        }
        
        // ✅ Security Check 5: Verify chain ID is supported
        const supportedChainIds = [1, 5, 56, 97]; // Mainnet, Goerli, BSC, BSC Testnet
        if (!supportedChainIds.includes(fields.data.chainId)) {
            return next(new ErrorHandler(`Unsupported chain ID: ${fields.data.chainId}`, 400));
        }
        
        // Normalize wallet address
        const walletAddress = fields.data.address.toLowerCase();
        
        // Find or create user with this wallet address
        let user = await User.findOne({ walletAddress });
        
        if (!user) {
            // Create new user with wallet address
            user = await User.create({
                walletAddress,
                name: `User_${fields.data.address.slice(0, 6)}`,
                email: `${walletAddress}@wallet.local`,
                authMethod: 'siwe',
                siweNonces: [{
                    nonce: fields.data.nonce,
                    usedAt: new Date()
                }]
            });
        } else {
            // Update existing user
            user.lastLoginAt = Date.now();
            
            // Store nonce to prevent replay
            if (!user.siweNonces) {
                user.siweNonces = [];
            }
            user.siweNonces.push({
                nonce: fields.data.nonce,
                usedAt: new Date()
            });
            
            // Keep only last 100 nonces to prevent database bloat
            if (user.siweNonces.length > 100) {
                user.siweNonces = user.siweNonces.slice(-100);
            }
            
            await user.save({ validateBeforeSave: false });
        }
        
        // Log successful authentication
        console.log(`SIWE authentication successful for ${walletAddress}`);
        
        // Send JWT token
        sendToken(user, 200, res);
        
    } catch (error) {
        console.error('SIWE verification failed:', error);
        
        // Provide specific error messages for debugging
        if (error.message.includes('Signature')) {
            return next(new ErrorHandler("Invalid signature", 401));
        } else if (error.message.includes('expired')) {
            return next(new ErrorHandler("Signature expired", 401));
        } else {
            return next(new ErrorHandler("Authentication failed", 401));
        }
    }
});

/**
 * Generate a nonce for SIWE authentication
 * 
 * ✅ SECURITY FIX: Provides cryptographically secure nonces
 */
exports.siweNonce = asyncErrorHandler(async (req, res, next) => {
    const crypto = require('crypto');
    
    // Generate cryptographically secure random nonce
    const nonce = crypto.randomBytes(16).toString('base64');
    
    res.status(200).json({
        success: true,
        nonce
    });
});

/**
 * Logout and invalidate SIWE session
 */
exports.siweLogout = asyncErrorHandler(async (req, res, next) => {
    res.cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
    });

    res.status(200).json({
        success: true,
        message: "Logged out successfully",
    });
});
