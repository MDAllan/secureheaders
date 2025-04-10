1. Clone the Repository 
Clone the repository to your local machine:

git clone <repository_url>
cd <repository_folder>

2. Install Dependencies
Make sure you have Node.js and npm (Node Package Manager) installed. You can check if they're installed by running:

node -v
npm -v

If Node.js and npm are installed, navigate to the project folder in the terminal and install the required dependencies by running:

npm install

This will install all the necessary packages listed in package.json.
3. Set Up Environment Variables
The server uses environment variables to manage sensitive information like database credentials, API keys, and JWT secrets. Create a .env file in the root directory of your project. Here is an example of what should go in the .env file:

# JWT Secret for token signing
JWT_SECRET=<your_secret_key>
JWT_REFRESH_SECRET=<your_refresh_secret_key>

# MongoDB URI (or other database)
DB_URI=<your_database_uri>

# Google OAuth credentials (for SSO login)
GOOGLE_CLIENT_ID=<your_google_client_id>
GOOGLE_CLIENT_SECRET=<your_google_client_secret>

# Encryption key for sensitive data
BIO_ENCRYPTION_KEY=<your_encryption_key>

Replace the placeholders (<your_secret_key>, <your_database_uri>, etc.) with your actual values.
4. Set Up Database
Ensure that you have a database running (e.g., MongoDB). Update the .env file with the correct database URI (DB_URI).
If you are using MongoDB locally, the URI might look like:

DB_URI=mongodb://localhost:27017/your_database_name

Make sure the MongoDB server is running on your local machine or that you have access to a remote MongoDB server.
5. Verify JWT Middleware (verifyToken.js)
Ensure that your verifyToken.js middleware is correctly set up (as discussed earlier). This middleware checks the validity of the JWT token and allows or denies access to protected routes.
6. Run the Server
Once everything is set up, start the server using the following command:

npm start

This will run the server on the default port (3000 if you're using Express.js). If you need to change the port, you can modify the server startup code in your server.js file like so:

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

7. Access the API
Once the server is running, you can access the API endpoints such as:
Login: POST /api/auth/login


Register: POST /api/auth/register


Logout: POST /api/auth/logout


Protected Route: GET /api/auth/dashboard (requires a valid JWT)


You can use tools like Postman to make requests or integrate the frontend to interact with these endpoints.
