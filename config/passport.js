import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import userModel from "../models/userModel.js";
import transporter from '../config/nodemailer.js'

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await userModel.findOne({ email: profile.emails[0].value });
        if (!user) {
          user = await userModel.create({
            name: profile.displayName,
            email: profile.emails[0].value,
            password: null, // or ""
            isAccountVerified: true,
            googleId: profile.id,
          });

          const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: profile.emails[0].value,
            subject: 'Welcome to Bandage',
            text: `Welcome to Auth website. Your account has been created with email id: ${profile.emails[0].value}`,
          }

          await transporter.sendMail(mailOptions);

        }
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await userModel.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

export default passport;