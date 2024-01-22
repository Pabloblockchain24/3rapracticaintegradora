import { Router } from "express";
import multer from "multer";
import { home, login, register, logout, emailRequestResetPassword, sendMail, passwordRequestResetPassword, resetPassword, uploadDocuments,uploadProducts, uploadProfiles, changeStatus} from "../controllers/user.controller.js"
import { storage } from "../controllers/user.controller.js";
const router = Router()

router.get("/", home)
router.post("/login", login)
router.post("/register", register)
router.post("/logout", logout)
router.get("/premium/:uid", changeStatus)

// routes asociadas a la restauracion del password
router.get("/emailRequestResetPassword", emailRequestResetPassword)
router.post("/sendMailReset", sendMail)
router.get("/passwordRequestResetPassword/:tid", passwordRequestResetPassword)
router.post("/resetPassword/:tid", resetPassword)


// route para subr archivos
const upload = multer({storage})

router.post("/:uid/documents", upload.fields([{ name: 'identificacion'},{ name: 'comprobante_domicilio'},{ name: 'estado_cuenta'}]), uploadDocuments)
router.post("/:uid/profiles", upload.single('perfil'), uploadProfiles)
router.post("/:uid/products", upload.single('product'), uploadProducts )


export default router