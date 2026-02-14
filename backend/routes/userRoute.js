const express = require('express');
const { registerUser, loginUser, logoutUser, getUserDetails, forgotPassword, resetPassword, updatePassword, updateProfile, getAllUsers, getSingleUser, updateUserRole, deleteUser } = require('../controllers/userController');
const { isAuthenticatedUser, authorizeRoles, rateLimit } = require('../middlewares/user_actions/auth');

const router = express.Router();

router.route('/register').post(rateLimit(5, 60 * 60 * 1000), registerUser);
router.route('/login').post(rateLimit(10, 15 * 60 * 1000), loginUser);
router.route('/logout').get(logoutUser);

router.route('/me').get(isAuthenticatedUser, getUserDetails);

router.route('/password/forgot').post(rateLimit(3, 60 * 60 * 1000), forgotPassword);
router.route('/password/reset/:token').put(rateLimit(5, 60 * 60 * 1000), resetPassword);

router.route('/password/update').put(isAuthenticatedUser, updatePassword);

router.route('/me/update').put(isAuthenticatedUser, rateLimit(5, 15 * 60 * 1000), updateProfile);

router.route("/admin/users").get(isAuthenticatedUser, authorizeRoles("admin"), getAllUsers);

router.route("/admin/user/:id")
    .get(isAuthenticatedUser, authorizeRoles("admin"), getSingleUser)
    .put(isAuthenticatedUser, authorizeRoles("admin"), updateUserRole)
    .delete(isAuthenticatedUser, authorizeRoles("admin"), deleteUser);

module.exports = router;






















