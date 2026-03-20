import mongoose from "mongoose";

async function connectDB() {
    return mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => {
        console.log("Connected to db");
    })
    .catch((err) => {
        console.log("Not connected :", err);
        throw err;
    });
}

export default connectDB;
