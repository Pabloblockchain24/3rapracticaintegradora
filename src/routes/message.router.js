import { Router } from "express";
import { createMessage } from "../controllers/message.controller.js";
import { userAuth } from "../middlewares/validate.js";

const router = Router()

router.post("/send", userAuth, createMessage)

export default router