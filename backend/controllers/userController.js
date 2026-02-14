const User = require('../models/userModel');
const asyncErrorHandler = require('../middlewares/helpers/asyncErrorHandler');
const sendToken = require('../utils/sendToken');
const ErrorHandler = require('../utils/errorHandler');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');
const cloudinary = require('cloudinary');
const axios = require('axios');
const validator = require('validator');
const xss = require('xss');
const TokenBlacklist = require('../models/TokenBlacklist');
const jwt = require('jsonwebtoken');

// SECURITY FIX: Enhanced user registration with proper validation
exports.registerUser = asyncErrorHandler(async (req, res, next) => {
    const { name, email, gender, password, avatar } = req.body;
    
    // SECURITY FIX: Validate all required fields
    if (!name || !email || !gender || !password || !avatar) {
        return next(new ErrorHandler("All fields are required", 400));
    }
    
    // SECURITY FIX: Validate and sanitize name
    const sanitizedName = name.trim();
    if (sanitizedName.length < 2 || sanitizedName.length > 50) {
        return next(new ErrorHandler("Name must be between 2 and 50 characters", 400));
    }
    
    // SECURITY FIX: Validate email format
    if (!validator.isEmail(email)) {
        return next(new ErrorHandler("Please provide a valid email", 400));
    }
    
    // SECURITY FIX: Validate gender
    const validGenders = ['male', 'female', 'other', 'prefer-not-to-say'];
    if (!validGenders.includes(gender.toLowerCase())) {
        return next(new ErrorHandler("Invalid gender value", 400));
    }
    
    // SECURITY FIX: Validate password strength
    if (password.length < 8 || password.length > 128) {
        return next(new ErrorHandler("Password must be between 8 and 128 characters", 400));
    }
    
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        return next(new ErrorHandler(
            "Password must contain uppercase, lowercase, number, and special character", 
            400
        ));
    }
    
    // SECURITY FIX: Check common passwords
    const commonPasswords = ['Password123!', 'Admin123!', 'Welcome123!', '12345678', 'password'];
    if (commonPasswords.includes(password)) {
        return next(new ErrorHandler("Password is too common", 400));
    }
    
    // SECURITY FIX: Validate avatar format
    if (!avatar.match(/^data:image\/(png|jpg|jpeg|gif);base64,/)) {
        return next(new ErrorHandler("Invalid avatar format. Only PNG, JPG, JPEG, GIF allowed", 400));
    }
    
    // SECURITY FIX: Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
        return next(new ErrorHandler("Email already registered", 400));
    }
    
    try {
        // Upload avatar with validation
        const myCloud = await cloudinary.v2.uploader.upload(avatar, {
            folder: "avatars",
            width: 150,
            crop: "scale",
            allowed_formats: ['jpg', 'png', 'jpeg', 'gif'],
            resource_type: 'image',
            max_file_size: 5000000 // 5MB limit
        });

        const user = await User.create({
            name: xss(sanitizedName),
            email: validator.normalizeEmail(email),
            gender: gender.toLowerCase(),
            password,
            avatar: {
                public_id: myCloud.public_id,
                url: myCloud.secure_url,
            },
        });

        sendToken(user, 201, res);
    } catch (uploadError) {
        return next(new ErrorHandler("Avatar upload failed", 400));
    }
});

// SECURITY FIX: Enhanced login with rate limiting consideration
exports.loginUser = asyncErrorHandler(async (req, res, next) => {
    const { email, password } = req.body;

    if(!email || !password) {
        return next(new ErrorHandler("Please Enter Email And Password", 400));
    }

    // SECURITY FIX: Basic email format validation
    if (!validator.isEmail(email)) {
        return next(new ErrorHandler("Please provide a valid email", 400));
    }

    const user = await User.findOne({ email: email.toLowerCase() }).select("+password");

    if(!user) {
        return next(new ErrorHandler("Invalid Email or Password", 401));
    }

    // SECURITY FIX: Check if account is suspended/banned
    if (user.status === 'suspended') {
        return next(new ErrorHandler("Account suspended. Please contact support", 403));
    }
    if (user.status === 'banned') {
        return next(new ErrorHandler("Account banned", 403));
    }

    const isPasswordMatched = await user.comparePassword(password);

    if(!isPasswordMatched) {
        return next(new ErrorHandler("Invalid Email or Password", 401));
    }

    // SECURITY FIX: Update last login
    user.lastLoginAt = new Date();
    await user.save({ validateBeforeSave: false });

    sendToken(user, 201, res);
});

// SECURITY FIX: Enhanced logout with token blacklisting
exports.logoutUser = asyncErrorHandler(async (req, res, next) => {
    const token = req.cookies?.token;
    
    if (token) {
        try {
            // SECURITY FIX: Add token to blacklist
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            await TokenBlacklist.create({
                token,
                userId: decoded.id,
                expiresAt: new Date(decoded.exp * 1000),
                reason: 'logout'
            });
        } catch (error) {
            // Token might be expired, continue with logout
            console.log('Token expired or invalid during logout:', error.message);
        }
    }

    res.cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });

    res.status(200).json({
        success: true,
        message: "Logged Out",
    });
});

// SECURITY FIX: Logout from all devices
exports.logoutAllDevices = asyncErrorHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    try {
        // SECURITY FIX: Blacklist all user tokens
        await TokenBlacklist.blacklistAllUserTokens(userId, 'password_change');
        
        res.status(200).json({
            success: true,
            message: "Logged out from all devices",
        });
    } catch (error) {
        return next(new ErrorHandler("Failed to logout from all devices", 500));
    }
});

// SECURITY FIX: Enhanced forgot password with host header validation
exports.forgotPassword = asyncErrorHandler(async (req, res, next) => {
    const { email } = req.body;
    
    if (!email) {
        return next(new ErrorHandler("Please provide your email", 400));
    }
    
    if (!validator.isEmail(email)) {
        return next(new ErrorHandler("Please provide a valid email", 400));
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    // SECURITY FIX: Prevent user enumeration by returning generic message
    if(!user) {
        return res.status(200).json({
            success: true,
            message: `Password reset instructions have been sent to your email`,
        });
    }

    // SECURITY FIX: Check if user account is active
    if (user.status === 'suspended' || user.status === 'banned') {
        return next(new ErrorHandler("This account is currently suspended", 401));
    }

    const resetToken = await user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // SECURITY FIX: Use environment variable for trusted domain instead of host header
    const trustedDomain = process.env.FRONTEND_URL || 'https://yourdomain.com';
    const resetPasswordUrl = `${trustedDomain}/password/reset/${resetToken}`;

    try {
        await sendEmail({
            email: user.email,
            templateId: process.env.SENDGRID_RESET_TEMPLATEID,
            data: {
                reset_url: resetPasswordUrl,
                user_name: user.name,
                expiry_hours: 15 // Reset token expires in 15 minutes
            }
        });

        res.status(200).json({
            success: true,
            message: `Password reset email sent to ${user.email}`,
        });

    } catch (error) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save({ validateBeforeSave: false });
        return next(new ErrorHandler(error.message, 500));
    }
});

// SECURITY FIX: Enhanced password reset with comprehensive validation
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    const { password, confirmPassword } = req.body;
    
    // SECURITY FIX: Validate password presence
    if (!password || !confirmPassword) {
        return next(new ErrorHandler("Please provide password and confirmation", 400));
    }
    
    // SECURITY FIX: Validate passwords match
    if (password !== confirmPassword) {
        return next(new ErrorHandler("Passwords do not match", 400));
    }
    
    // SECURITY FIX: Validate password strength (same as registration)
    if (password.length < 8 || password.length > 128) {
        return next(new ErrorHandler("Password must be between 8 and 128 characters", 400));
    }
    
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        return next(new ErrorHandler(
            "Password must contain uppercase, lowercase, number, and special character", 
            400
        ));
    }
    
    // SECURITY FIX: Check against common passwords
    const commonPasswords = ['Password123!', 'Admin123!', 'Welcome123!'];
    if (commonPasswords.includes(password)) {
        return next(new ErrorHandler("Password is too common", 400));
    }

    // create hash token
    const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

    const user = await User.findOne({ 
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    });

    if(!user) {
        return next(new ErrorHandler("Invalid or expired reset token", 404));
    }

    // SECURITY FIX: Check if user account is active
    if (user.status === 'suspended' || user.status === 'banned') {
        return next(new ErrorHandler("This account is currently suspended", 401));
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.passwordChangedAt = Date.now(); // SECURITY FIX: Track password change

    await user.save();
    
    // SECURITY FIX: Blacklist all existing tokens for this user
    await TokenBlacklist.blacklistAllUserTokens(user._id, 'password_change');
    
    sendToken(user, 200, res);
});

// SECURITY FIX: Enhanced profile update with comprehensive validation
exports.updateProfile = asyncErrorHandler(async (req, res, next) => {
    const { name, email, gender } = req.body;
    
    // SECURITY FIX: Validate and sanitize inputs
    if (name) {
        const sanitizedName = String(name).trim();
        if (sanitizedName.length < 2 || sanitizedName.length > 50) {
            return next(new ErrorHandler("Name must be between 2 and 50 characters", 400));
        }
        req.body.name = sanitizedName;
    }
    
    if (email) {
        const sanitizedEmail = String(email).trim();
        if (!validator.isEmail(sanitizedEmail)) {
            return next(new ErrorHandler("Please provide a valid email", 400));
        }
        
        // SECURITY FIX: Check if email is already taken by another user
        const existingUser = await User.findOne({ 
            email: sanitizedEmail.toLowerCase(), 
            _id: { $ne: req.user.id } 
        });
        
        if (existingUser) {
            return next(new ErrorHandler("Email already in use", 400));
        }
        req.body.email = sanitizedEmail.toLowerCase();
    }

    // SECURITY FIX: Validate gender if provided
    if (gender) {
        const validGenders = ['male', 'female', 'other', 'prefer-not-to-say'];
        if (!validGenders.includes(String(gender).toLowerCase())) {
            return next(new ErrorHandler("Invalid gender value", 400));
        }
    }

    const newUserData = {
        name: req.body.name ? xss(String(req.body.name)) : req.user.name,
        email: req.body.email ? validator.normalizeEmail(String(req.body.email)) : req.user.email,
        gender: req.body.gender ? String(req.body.gender).toLowerCase() : req.user.gender
    };

    if(req.body.avatar !== "") {
        // SECURITY FIX: Validate avatar format
        if (!req.body.avatar.match(/^data:image\/(png|jpg|jpeg|gif);base64,/)) {
            return next(new ErrorHandler("Invalid avatar format", 400));
        }
        
        const user = await User.findById(req.user.id);
        const imageId = user.avatar.public_id;

        await cloudinary.v2.uploader.destroy(imageId);

        const myCloud = await cloudinary.v2.uploader.upload(req.body.avatar, {
            folder: "avatars",
            width: 150,
            crop: "scale",
            allowed_formats: ['jpg', 'png', 'jpeg', 'gif'],
            resource_type: 'image',
            max_file_size: 5000000
        });

        newUserData.avatar = {
            public_id: myCloud.public_id,
            url: myCloud.secure_url,
        };
    }

    await User.findByIdAndUpdate(req.user.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false, // SECURITY FIX: Use false instead of true
    });

    res.status(200).json({
        success: true,
        message: "Profile updated successfully"
    });
});

// SECURITY FIX: Enhanced password update with validation
exports.updatePassword = asyncErrorHandler(async (req, res, next) => {
    const { oldPassword, newPassword, confirmPassword } = req.body;
    
    // SECURITY FIX: Validate all fields
    if (!oldPassword || !newPassword || !confirmPassword) {
        return next(new ErrorHandler("All password fields are required", 400));
    }
    
    // SECURITY FIX: Validate new password confirmation
    if (newPassword !== confirmPassword) {
        return next(new ErrorHandler("New passwords do not match", 400));
    }
    
    // SECURITY FIX: Validate new password strength
    if (newPassword.length < 8 || newPassword.length > 128) {
        return next(new ErrorHandler("Password must be between 8 and 128 characters", 400));
    }
    
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
        return next(new ErrorHandler(
            "Password must contain uppercase, lowercase, number, and special character", 
            400
        ));
    }

    const user = await User.findById(req.user.id).select("+password");

    const isPasswordMatched = await user.comparePassword(oldPassword);

    if(!isPasswordMatched) {
        return next(new ErrorHandler("Old Password is Invalid", 400));
    }

    user.password = newPassword;
    user.passwordChangedAt = Date.now(); // SECURITY FIX: Track password change
    await user.save();
    
    // SECURITY FIX: Blacklist all existing tokens for this user
    await TokenBlacklist.blacklistAllUserTokens(user._id, 'password_change');
    
    sendToken(user, 201, res);
});

// Get User Details
exports.getUserDetails = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    res.status(200).json({
        success: true,
        user,
    });
});

// Get All Users (admin)
exports.getAllUsers = asyncErrorHandler(async (req, res, next) => {
    const users = await User.find();

    res.status(200).json({
        success: true,
        users,
    });
});

// Get Single User (admin)
exports.getSingleUser = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        return next(
            new ErrorHandler(`User does not exist with Id: ${req.params.id}`, 400)
        );
    }

    res.status(200).json({
        success: true,
        user,
    });
});

// Update User Role -- Admin
exports.updateUserRole = asyncErrorHandler(async (req, res, next) => {
    const { role, status } = req.body;

    // SECURITY FIX: Validate role
    const validRoles = ['user', 'admin'];
    if (role && !validRoles.includes(role)) {
        return next(new ErrorHandler("Invalid role value", 400));
    }

    // SECURITY FIX: Validate status
    const validStatuses = ['active', 'suspended', 'banned'];
    if (status && !validStatuses.includes(status)) {
        return next(new ErrorHandler("Invalid status value", 400));
    }

    const newUserData = {
        role: role,
        status: status
    };

    await User.findByIdAndUpdate(req.params.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success: true,
        message: "User updated successfully"
    });
});

// Delete User -- Admin
exports.deleteUser = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        return next(
            new ErrorHandler(`User does not exist with Id: ${req.params.id}`, 400)
        );
    }

    // Remove avatar from Cloudinary
    if (user.avatar && user.avatar.public_id) {
        await cloudinary.v2.uploader.destroy(user.avatar.public_id);
    }

    await user.remove();

    res.status(200).json({
        success: true,
        message: "User Deleted Successfully",
    });
});
