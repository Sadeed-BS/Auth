import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, default: null},
    verifyOtp: {type: String, default: ''},
    verifyOtpExpireAt: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false},
    resetOtp: {type: String, default: ''},
    resetOtpExpireAt: {type: Number, default: 0},
    googleId: { type: String, default: "" },
    refreshToken: { type: String, default: "" },
    isAdmin: { type: Boolean, default: false },
})

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;