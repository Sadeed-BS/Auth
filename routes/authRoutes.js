import express from 'express'
import { googlecallback, isAuthenticated, login, logout, register, resetPassword, sendResetOtp, sendVerifyOtp, verifyEmail } from '../controllers/authController.js'
import userAuth from '../middlewere/userAuth.js';
import passport from "../config/passport.js";
import jwt from "jsonwebtoken";
import { refreshToken } from '../controllers/authController.js';

const authRouter = express.Router();


authRouter.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

authRouter.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false,
  }), 
  
  googlecallback
  
);

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);     
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp);     
authRouter.post('/verify-account', userAuth, verifyEmail);     
authRouter.get('/is-auth', userAuth, isAuthenticated);     
authRouter.post('/send-reset-otp', sendResetOtp);     
authRouter.post('/reset-password', resetPassword);   
authRouter.post('/refresh-token', refreshToken);  

export default authRouter;