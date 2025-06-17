
# User Auth & Admin API

This project is a Node.js/Express backend for user authentication (including Google OAuth), email verification, password reset, and admin management. It uses MongoDB for storage and Nodemailer for sending emails.

## 🚀 Setup Instructions

### 1. Clone the Repository

```sh
git clone https://github.com/Sadeed-BS/Auth.git
cd tedx
```
### 2. Install Dependencies

```sh
npm install
```

### 3. Configure Environment Variables

Edit the .env file with your MongoDB, SMTP, and Google OAuth credentials.

### 4. Start the Server

```sh
npm run server
```

The server will run on ```http://localhost:4000.```

## 🗂️ Project Structure

- ```server.js``` - Main entry point
- ```config/``` - Database, email, and passport configs
- ```controllers/``` - Business logic for users, auth, and Admin
- ```models/``` - Mongoose user model
- ```routes/``` - Express routers for auth, user, and admin
- ```middlewere/``` - Authentication and admin middleware

```
.env
package.json
README.md
server.js
config/
  emailTemplates.js
  mongodb.js
  nodemailer.js
  passport.js
controllers/
  adminController.js
  authController.js
  userController.js
middlewere/
  adminAuth.js
  userAuth.js
models/
  userModel.js
routes/
  adminRoutes.js
  authRoutes.js
  userRoutes.js
```


## 📚 API Endpoints
Auth APIs (```/api/auth```)

- POST ```/register```
Register a new user
Body: 
```
{ 
  "name": "User", 
  "email": "user@email.com", 
  "password": "pass" 
}
```

- POST ```/login```
Login with email and password
Body: 
```
{ 
  "email": "user@email.com", 
  "password": "pass" 
}
```

- POST ```/logout```
Logout user (clears cookies)

- GET ```/google```
Start Google OAuth login (redirects to Google)

- GET ```/google/callback```
Google OAuth callback (handled internally)

- POST ```/send-verify-otp```
Send email verification OTP
#### Requires Auth Cookie

- POST ```/verify-account```
Verify email with OTP
Body: 
```
{ 
  "userId": "<userId>", 
  "otp": "<otp>" 
}
```

#### Requires Auth Cookie


- GET ```/is-auth```
Check if user is authenticated
#### Requires Auth Cookie

- POST ```/send-reset-otp```
Send password reset OTP
Body: 
```
{ 
  "email": "user@email.com" 
}
```

- POST ```/reset-password```
Reset password with OTP
Body: 
```
{ 
  "email": "user@email.com", 
  "otp": "123456", 
  "newPassword": "newpass" 
}
```

- POST ```/refresh-token```
Refresh JWT access token using refresh token cookie

#

User APIs ```(/api/user)```

- GET ```/data```
Get current user data (name, verification status)
#### Requires Auth Cookie

#

Admin APIs ```(/api/admin)``` (Admin Only)

- POST ```/users```
Get all users (except passwords and refresh tokens)
Requires Admin Auth Cookie

## 🧪 How to Test APIs

You can use [Postman](https://www.postman.com) or [curl](https://curl.se) to test the APIs.

#### Example: Register
```
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Admin","email":"admin@email.com","password":"adminpass"}' \
  -c cookies.txt
```

#### Example: Login

```
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@email.com","password":"adminpass"}' \
  -c cookies.txt
```

#### Example: Get User Data

````
curl -X GET http://localhost:4000/api/user/data \
  -b cookies.txt
````

#### Example: Admin Get All Users

```
curl -X POST http://localhost:4000/api/admin/users \
  -b cookies.txt
```
#
- For protected routes, you must include the cookies set by login/register (```-b cookies.txt```).
- To make a user admin, update their ```isAdmin``` field in MongoDB.

## Google OAuth

- Visit http://localhost:4000/api/auth/google in your browser to start Google login.
- After login, you will be redirected based on your admin status.

## 📝 Notes

- All cookies are HTTP-only for security.
- JWT access tokens expire in 15 minutes; refresh tokens in 7 days.
- Email verification and password reset use OTPs sent via email.
- Admin routes require the user to have ```isAdmin: true```.


## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`MONGODB_URL=your_mongodb_url`

`JWT_SECRET=your_jwt_secret`

`NODE_ENV=development`


`SMTP_USER=your_smtp_user`

`SMTP_PASS=your_smtp_pass`

`SENDER_EMAIL=your_sender_email`


`GOOGLE_CLIENT_ID=your_google_client_id`

`GOOGLE_CLIENT_SECRET=your_google_client_secret`

`GOOGLE_CALLBACK_URL=http://localhost:4000/api/auth/google/callback`

