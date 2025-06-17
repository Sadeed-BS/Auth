import userModel from '../models/userModel.js';

export const getAllUsers = async (req, res) => {
    try {
        const users = await userModel.find({}, '-password -refreshToken');
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};