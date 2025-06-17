import express from 'express';
import { getAllUsers } from '../controllers/adminController.js';
import userAuth from '../middlewere/userAuth.js';
import adminAuth from '../middlewere/adminAuth.js';

const adminRouter = express.Router();

adminRouter.post('/users', userAuth, adminAuth, getAllUsers);

export default adminRouter;