import { Router } from "express";
import { home, login, register, logout, changeRol, emailRequestResetPassword, sendMail, passwordRequestResetPassword, resetPassword} from "../controllers/user.controller.js"

const router = Router()

router.get("/", home)
router.post("/login", login)
router.post("/register", register)
router.post("/logout", logout)
router.put("/premium/:uid", changeRol)

// routes asociadas a la restauracion del password
router.get("/emailRequestResetPassword", emailRequestResetPassword)
router.post("/sendMailReset", sendMail)
router.get("/passwordRequestResetPassword/:tid", passwordRequestResetPassword)
router.post("/resetPassword/:tid", resetPassword)



export default router