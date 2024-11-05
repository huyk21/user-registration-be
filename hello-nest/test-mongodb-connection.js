const { MongoClient, ServerApiVersion } = require('mongodb');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

// Get the MongoDB URI from environment variables
const uri = process.env.DB_URL;

// Create a new MongoClient instance
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function testConnection() {
  try {
    // Attempt to connect to MongoDB
    await client.connect();
    console.log('✅ Successfully connected to MongoDB!');

    // Send a ping to confirm the connection is active
    await client.db('admin').command({ ping: 1 });
    console.log('Pinged your MongoDB deployment. Connection is confirmed.');

  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
  } finally {
    // Close the MongoDB client connection
    await client.close();
  }
}

// Run the test
testConnection().catch(console.error);
