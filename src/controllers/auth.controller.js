import userModel from "../models/user.model.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import sessionModel from "../models/session.model.js"

async function registerController(req, res) {

    const { username, email, password } = req.body

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Please provide all the required fields",
        });
    }

    const userExists = await userModel.findOne({ email })

    if (userExists) {
        return res.status(409).json({
            message: "Account already exists with this email"
        })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })

    const refreshToken = jwt.sign(
        { id: user._id, username: user.username, email: user.email},
        process.env.JWT_SECRET,
        {expiresIn: "7d"}
    )

    const refreshTokenHash = await bcrypt.hash(refreshToken, 10)

    const session = await sessionModel.create({
        user: user._id,
        refreshToken: refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    });

    const accessToken = jwt.sign(
        { id: user._id, sessionId: session._id },
        process.env.JWT_SECRET,
        {expiresIn: "10m"}
    )

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(201).json({
        message: "User registered sucessfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        },
        accessToken: accessToken
    })
}

async function refreshTokenController(req, res) {

    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
        return res.status(401).json({
            message: "Unauthorized. Login first!"
        })
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET)

    const session = await sessionModel.findOne({
        user: decoded.id,
        revoked: false
    })

    if (!session) {
        return res.status(400).json({
            message: "Invalid session. Login first!"
        })
    }

    const matchToken = await bcrypt.compare(refreshToken, session.refreshToken)
    console.log(matchToken);
    

    if (!matchToken) {
        return res.status(400).json({
            message: "Invalid refresh token"
        })
    }

    const accessToken = jwt.sign(
        { id: decoded.id, sessionId: session._id },
        process.env.JWT_SECRET,
        {expiresIn: "10m"}
    )

    const newRefreshToken = jwt.sign(
        { id: decoded.id, sessionId: session._id },
        process.env.JWT_SECRET,
        {expiresIn: "7d"}
    )

    session.refreshToken = await bcrypt.hash(newRefreshToken, 10);
    await session.save()

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(200).json({
        message: "Access token refreshed sucessfully",
        accessToken: accessToken
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

    const refreshToken = jwt.sign(
        { id: user._id, username: user.username, email: user.email },
        process.env.JWT_SECRET,
        {expiresIn: "7d"}
    )

    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    const session = await sessionModel.create({
        user: user._id,
        refreshToken: refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    });

    const accessToken = jwt.sign(
        { id: user._id, sessionId: session._id },
        process.env.JWT_SECRET,
        {expiresIn: "10m"}
    )

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })

    return res.status(200).json({
        message: "User logged in sucessfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        },
        accessToken: accessToken
    })
}

async function getMeController(req, res) {
    const token = req.headers.authorization?.split(" ")[1]

    if (!token) {
        return res.status(401).json({
            message: "Unauthorized. Login first!",
        });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    const user = await userModel.findById(decoded.id)

    if (!user) {
        return res.status(401).json({
            message: "Unauthorized. Login first!"
        })
    }

    return res.status(200).json({
        message: "User details fetched",
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    })
}

async function logoutController(req, res) {

    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
        return res.status(401).json({
            message: "Unauthorized. Login first!",
        });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET)

    const session = await sessionModel.findOne({
        user: decoded.id,
        revoked: false
    })

    if (!session) {
        return res.status(401).json({
            message: "Invalid session. Login first!"
        })
    }

    const matchToken = await bcrypt.compare(refreshToken, session.refreshToken)

    if (!matchToken) {
        return res.status(401).json({
            message: "Invalid refresh token. Login first!"
        })
    }

    session.revoked = true
    await session.save()

    res.clearCookie("refreshToken")

    return res.status(200).json({
        message: "Logged out sucessfully"
    })
}

async function logoutAllController(req, res) {

    const refreshToken = req.cookies.refreshToken

    if (!refreshToken) {
        return res.status(401).json({
            message: "Unauthorized. Login first!"
        })
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET)

    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false
    }, {
        revoked: true
    })

    res.clearCookie("refreshToken")

    return res.status(200).json({
        message: "Logged out from all devices"
    })
}


export default {
    registerController,
    refreshTokenController,
    loginController,
    getMeController,
    logoutController,
    logoutAllController,
}