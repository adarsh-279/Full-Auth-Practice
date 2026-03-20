import { Router } from "express";
import authController from "../controllers/auth.controller.js";

const authRouter = Router()

authRouter.post("/register", authController.registerController)
authRouter.post("/login", authController.loginController)
authRouter.get("/getMe", authController.getMeController)

export default authRouter