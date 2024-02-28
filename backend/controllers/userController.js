import User from "../models/userModel.js";
import asyncHandler from "../middlewares/asyncHandler.js";
import bcrypt from "bcryptjs";
import createToken from "../utils/createToken.js";

const createUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    //Checking the required Inputs
    if (!username || !email || !password) {
        throw new Error("Please fill all the inputs!");
    }

    //Checking Existing Users
    const userExists = await User.findOne({ email });
    if (userExists) {
        res.status(400).send("User already exists");
    }

    //Hashing The Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ username, email, password: hashedPassword });

    //Creating Token to be saved in cookies
    try {
        await newUser.save();
        createToken(res, newUser._id);

        res.status(201).json({
            _id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            isAdmin: newUser.isAdmin,
        });

    } catch (error) {
        res.status(400);
        throw new Error("Invalid User Data");
    }
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const exisitngUser = await User.findOne({ email });

    if (exisitngUser) {
        const isPasswordVaild = await bcrypt.compare(
            password,
            exisitngUser.password
        );

        if (isPasswordVaild) {
            createToken(res, exisitngUser._id);

            res.status(201).json({
                _id: exisitngUser._id,
                username: exisitngUser.username,
                email: exisitngUser.email,
                isAdmin: exisitngUser.isAdmin,
            });
            return;
        }
    }
});

const logoutCurrentUser = asyncHandler(async (req, res) => {
    res.cookie('jwt', '', {
        httyOnly: true,
        expires: new Date(0),
    })
    res.status(200).json({ message: "Logged out Successfully!" })
});

const getAllUsers = asyncHandler(async (req, res) => {
    const users = await User.find({});
    res.json(users);
});

const getCurrentUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    if (user) {
        res.json({
            _id: user._id,
            username: user.username,
            email: user.email
        })
    } else {
        res.status(404);
        throw new Error("User Not Found!");
    }

});

const updateCurrentProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)
    if (user) {
        user.username = req.body.username || user.username;
        user.email = req.body.email || user.email;
        if (req.body.password) {
            //Hashing The Password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            user.password = hashedPassword;
        }
        const updatedUser = await user.save();
        
        res.json({
            _id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            isAdmin: updatedUser.isAdmin
        });
    } else {
        res.status(404);
        throw new Error("User not Found!")
    }
    
});

const deleteUserById = asyncHandler(async(req,res) => {
    const user = await User.findById(req.params.id);

    if(user){
        if(user.admin){
            res.status(404);
            throw new Error("Cannot delete admin user");
        }

        await User.deleteOne({_id:user._id});
        res.json({ message:"User Removed"});
    }else{
        res.status(404);
        throw new Error("User not Found.");
    }
});

const getUserById = asyncHandler(async(req,res) =>{
    const user = await User.findById(req.params.id).select("-password");

    if (user) {
        res.json(user);
    } else {
        res.status(404);
        throw new Error("User Not Found!");
    }
})

const updateUserById = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id)
    if (user) {
        user.username = req.body.username || user.username;
        user.email = req.body.email || user.email;
        user.isAdmin = Boolean(req.body.isAdmin);
        const updatedUser = await user.save();
    
        res.json({
            _id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            isAdmin: updatedUser.isAdmin
        });
    } else {
        res.status(404);
        throw new Error("User not Found!");
    }
    
});


export { 
    createUser, 
    loginUser, 
    logoutCurrentUser, 
    getAllUsers, 
    getCurrentUserProfile, 
    updateCurrentProfile,deleteUserById,
    getUserById,
    updateUserById 
};