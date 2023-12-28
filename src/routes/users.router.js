import { Router } from "express";
import { home, login, register, logout} from "../controllers/user.controller.js"

const router = Router()

router.get("/", home)
router.post("/login", login)
router.post("/register", register)
router.post("/logout", logout)

export default router