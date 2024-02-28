//packages
import path from 'path';
import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';


//Utilites
import ConnectDB from './config/db.js';
import userRoutes from "./routes/userRoutes.js"

dotenv.config();
const port = process.env.PORT || 5000;

ConnectDB();

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

app.use("/api/users",userRoutes);

app.get("/",(req,res)=>{
    res.send("Hello");
})

app.listen(port,() => {
    console.log(`Server Running on port: ${port}`);
})