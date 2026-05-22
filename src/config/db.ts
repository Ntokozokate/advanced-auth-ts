import mongoose from "mongoose";

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("Mongodb connected successfully");
  } catch (err) {
    console.error("MongoDB connection error !");
    process.exit(1);
  }
}
