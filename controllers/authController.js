import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) => {

    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message: 'Missing Details'});
    }

    try {
        
        const existingUser = await userModel.findOne({email});

        if(existingUser){
            return res.json({success: false, message: 'User already exists'});
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password:hashedPassword});
        await user.save();
        const accessToken = generateAccessToken(user._id);
        const refreshToken = generateRefreshToken(user._id);

        user.refreshToken = refreshToken;
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 60 * 60 * 1000
        });

        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Bandage',
            text: `Welcome to Auth website. Your account has been created with email id: ${email}`,
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true, isAdmin: user.isAdmin});

    } catch (error) {
        res.json({success: false, message: error.message})
    }

}

export const login = async (req, res) => {

    const {email, password} = req.body;
    
    if (!email || !password) {
        return res.json({success: false, message: 'Email and password are required'})
    }

    try {

        const user = await userModel.findOne({email});

        if (!user) {
            return res.json({success: false, message: 'Invalid email'})
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({success: false, message: 'Invalid password'})
        }

        const accessToken = generateAccessToken(user._id);
        const refreshToken = generateRefreshToken(user._id);

        user.refreshToken = refreshToken;
        await user.save();
        
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 60 * 60 * 1000
        })

        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        return res.json({success: true, isAdmin: user.isAdmin});

    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

export const logout = async (req, res) => {
    
    try {

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        if (req.user && req.user.id) {
            await userModel.findByIdAndUpdate(req.user.id, { refreshToken: "" });
        }

        return res.json({success: true, message: 'Logged Out'})

    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

export const sendVerifyOtp = async (req, res) => {
    try {

        const { userId } = req.body;
        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({success: false, message: 'Account Already verified'})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            //text: `Your OTP is ${otp}. Verify your account using this OTP`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions);

        res.json({success: true, message: 'Verification OTP Sent on Email'});

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

export const verifyEmail = async (req, res) => {

    const { userId, otp } = req.body;

    if ( !userId || !otp) {
        return res.json({success: false, message: "Missing Details"});
    }
    
    try {

        const user = await userModel.findById(userId);

        if ( !user ) {
            return res.json({success: false, message: "User Not found"});
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({success: false, message: "Invalid OTP"});
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({success: false, message: "OTP Expired"});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Email verified successfully"});
        
    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

export const isAuthenticated = async (req, res) => {

    try {
        return res.json({success: true})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

export const sendResetOtp = async (req, res) => {

    const { email } = req.body;
    
    if (!email) {
        return res.json({success: false, message: "Email is required"})
    }

    try {

        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({success: false, message: "User not found"})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            //text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true, message: 'OTP sent to your email'})
        
    } catch (error) {
        return res.json({success: false, message: error.message})
    }

}

export const resetPassword = async (req, res) => {

    const { email, otp, newPassword } = req.body;

    if ( !email || !otp || !newPassword) {
        return res.json({success: false, message: "Email, OTP, New password are required"})
    }

    try {

        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({success: false, message: "User not found"});
        }
        
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({success: false, message: "Invalid OTP"});
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({success: false, message: "OTP Expired"});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: "Password has been reset successfully"});
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    }

}

export const generateAccessToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

export const generateRefreshToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

export const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            return res.status(401).json({ success: false, message: 'No refresh token provided' });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ success: false, message: 'Invalid refresh token' });
        }

        const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
        res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        return res.json({ success: true });
    } catch (error) {
        return res.status(403).json({ success: false, message: 'Invalid or expired refresh token' });
    }
};

export const googlecallback = async (req, res) => {
    const accessToken = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Save refreshToken to DB
    await userModel.findByIdAndUpdate(req.user._id, { refreshToken });

    res.cookie("token", accessToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 15 * 60 * 1000,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const user = await userModel.findById(req.user._id);

    if (user && user.isAdmin) {
      return res.redirect("http://localhost:4000/admin");
    } else {
      return res.redirect("http://localhost:4000");
    }
  }