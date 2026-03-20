import userModel from "../models/user.model.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

async function registerController(req, res) {

    const { username, email, password } = req.body

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Please provide all the required fields",
        });
    }

    const userExists = await userModel.findOne({ email })

    if (userExists) {
        return res.status(400).json({
            message: "Account already exists with this email"
        })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })

    const token = jwt.sign(
        { id: user._id, username: user.username },
        process.env.JWT_SECRET,
        {expiresIn: "1d"}
    )

    res.cookie("token", token)

    res.status(201).json({
        message: "User registered sucessfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}

async function loginController(req, res) {
    const { email, password } = req.body
    
    if ( !email || !password) {
        return res.status(400).json({
            message: "Please provide all the required fields",
        });
    }

    const user = await userModel.findOne({ email })

    if (!user) {
        return res.status(400).json({
            message: "Invaid email or password"
        })
    }
    
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(400).json({
            message: "Invaid email or password",
        });
    }

    const token = jwt.sign(
        { id: user._id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
    )

    res.cookie("token", token)

    return res.status(201).json({
        message: "User logged in sucessfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}

async function getMeController(req, res) {
    const token = req.headers.authorization?.split(" ")[1]

    if (!token) {
        return res.status(401).json({
            message: "Token not found"
        })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    console.log(decoded);

    const user = await userModel.findById(decoded.id)

    return res.status(200).json({
        message: "User details fetched",
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    })
}


export default {
    registerController,
    loginController,
    getMeController,
}