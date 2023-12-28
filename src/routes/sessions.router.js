import { Router } from "express";
const router = Router()
import { autenticar } from "../controllers/session.controller.js";

router.get("/current", autenticar)

export default router