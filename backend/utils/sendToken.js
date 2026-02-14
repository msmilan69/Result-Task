const sendToken = (user, statusCode, res) => {
    // Create JWT token
    const token = user.getJWTToken();

    // SECURITY FIX: Enhanced cookie options with security flags
    const options = {
        expires: new Date(
            Date.now() + (process.env.COOKIE_EXPIRE || 7) * 24 * 60 * 60 * 1000
        ),
        httpOnly: true, // Prevents XSS attacks
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'strict', // Prevents CSRF attacks
        path: '/', // Restrict to specific path if needed
        domain: process.env.COOKIE_DOMAIN || undefined // Restrict to specific domain
    };

    // SECURITY FIX: Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');

    res.status(statusCode)
       .cookie('token', token, options)
       .json({
        success: true,
        user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            avatar: user.avatar
        },
        token // Only include token in response for initial login
    });
};

module.exports = sendToken;
