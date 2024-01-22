import bcrypt from "bcrypt"
import { createAccessToken, createResetToken } from "../utils.js"
import jwt from "jsonwebtoken"
import config from "../config/config.js"
import nodemailer from "nodemailer"
import multer from "multer"

import { usersService, cartsService } from "../repositories/index.js"

export const logout = async (req, res) => {
    res.cookie("token", "", {
        expires: new Date(0)
    })
    res.redirect("/api/users")
    return
}

export const register = async (req, res) => {
    const { first_name, last_name, email, age, password, role } = req.body

    try {
        const userFound = await usersService.getUserByEmail(email)
        if (userFound) return res.status(400).json(["El email ya esta registrado"])

        const hash = await bcrypt.hashSync(password, bcrypt.genSaltSync(10))

        const newUser = { first_name, last_name, email, age, role }
        newUser.password = hash
        newUser.cart = await cartsService.createCart()

        await usersService.createUser(newUser)

        res.json({
            id: newUser._id,
            first_name: newUser.first_name,
            last_name: newUser.last_name,
            email: newUser.email,
            age: newUser.age,
            cart: newUser.cart,
            role: newUser.role
        })
    } catch (error) {
        console.log(error)
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body
    const userFound = await usersService.getUserByEmail(email)
    if (!userFound) return res.status(401).json({ message: "Usuario no encontrado" })

    const isMatch = await bcrypt.compareSync(password, userFound.password)
    if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" })

    const token = await createAccessToken({ id: userFound._id })
    res.cookie("token", token)

    userFound.last_connection = Date.now()
    await usersService.updateUserById(userFound._id, userFound)


    const cartFound = await cartsService.getCartById(userFound.cart)

    res.render("profile.hbs", {
        first_name: userFound.first_name,
        last_name: userFound.last_name,
        email: userFound.email,
        age: userFound.age,
        cart: cartFound.products,
        role: userFound.role,
        id: userFound._id,
        status: userFound.role
    })
}

export const home = async (req, res) => {
    const { token } = req.cookies
    if (!token) {
        return res.render("home.hbs", {
            title: "Vista login"
        })
    }
    jwt.verify(token, config.TOKEN_SECRET, async (err, user) => {
        if (err) return res.status(403).json({ message: "Token invalido" })
        const userFound = await usersService.getById(user.id)
        const cartFound = await cartsService.getCartById(userFound.cart)
        res.render("profile.hbs", {
            first_name: userFound.first_name,
            last_name: userFound.last_name,
            email: userFound.email,
            age: userFound.age,
            cart: cartFound.products,
            role: userFound.role,
            idcart: cartFound._id,
            id: userFound._id,
            status: userFound.role
        })
    })
}

export const changeRol = async (uid) => {
    const userFound = await usersService.getById(uid)

    if (userFound.role === "premium") {
        userFound.role = "user"
        await usersService.updateUserById(uid, userFound);
        return { result: "success", message: "Usuario cambio de rol de premium a user" };
    } else if (userFound.role === "user") {
        if (userFound.documentos.length >= 3) {
            userFound.role = "premium"
            await usersService.updateUserById(userFound._id, userFound)
            return { result: "success", message: "Usuario cambio de rol de user a premium" };
        } else {
            throw { status: 400, message: 'Usuario no ha terminado de procesar su documentacion' };
        }
    } else {
        throw { status: 401, message: "Cambio de rol no es posible, no es ni user ni premium" };
    }
}

export const changeStatus = async (req, res) => {
    const uid = req.params.uid
    const userFound = await usersService.getById(uid)

    if (userFound.role === "premium") {
        userFound.role = "user"
        await usersService.updateUserById(uid, userFound);
        res.send({ result: "success", message: "Usuario cambio de rol de premium a user" })
    } else if (userFound.role === "user") {
        if (userFound.documentos.length >= 3) {
            userFound.role = "premium"
            await usersService.updateUserById(userFound._id, userFound)
            res.send({ result: "success", message: "Usuario cambio de rol de user a premium" })
        } else {
            res.send({ result: "error", message: "Usuario no ha terminado de procesar su documentacion" })
        }
    } else {
        res.send({ result: "error", message: "Cambio de rol no es posible, no es ni user ni premium" })
    }
}

export const emailRequestResetPassword = async (req, res) => {
    res.render("emailRequestResetPassword.hbs", {})
}

export const sendMail = async (req, res) => {
    const { email } = req.body
    let user = await usersService.getUserByEmail(email)
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

    const resetToken = await createResetToken({ id: user._id })
    user.resetToken = resetToken;
    await usersService.updateUserById(user._id, user);
    const resetLink = `http://localhost:8080/api/users/passwordRequestResetPassword/${resetToken}`

    const transporter = nodemailer.createTransport({
        service: "gmail",
        port: 587,
        auth: {
            user: "parcepaiva@gmail.com",
            pass: "yydj uzct rbyg bluz"
        }
    })
    const mailOptions = {
        from: "CoderTienda contact <parcepaiva@gmail.com>",
        to: `${email}`,
        subject: `Recuperacion contraseña ${email}`,
        html: `
        <html>
            <head>
            </head>
            <body>
                <div> Para restablecer tu contraseña, haz clic en el siguiente enlace: ${resetLink} </div>
            </body>
        </html>`
    }
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error)
            res.send("Error al enviar correo")
        } else {
            res.send(`Correo enviado`)
        }
    })


}

export const passwordRequestResetPassword = async (req, res) => {
    const token = req.params.tid;
    const userFound = await usersService.getUserByResetToken(token)
    if (!userFound) return res.render("emailRequestResetPassword.hbs", { title: "Token de restablecimiento expiro o no es valido, intente nuevamente" })
    res.render('passwordRequestResetPassword.hbs', { token });

}

export const resetPassword = async (req, res) => {
    const token = req.params.tid;
    const { password } = req.body
    let userFound = await usersService.getUserByResetToken(token)

    const isSamePassword = await bcrypt.compare(password, userFound.password)
    if (isSamePassword) {
        return res.render('passwordRequestResetPassword.hbs', { token, title: "Contraseña debe ser distinta a la anterior" });
    }
    const hash = await bcrypt.hashSync(password, bcrypt.genSaltSync(10))
    userFound.password = hash
    await usersService.updateUserById(userFound._id, userFound);
    res.send({ result: "success", message: "Contraseña actualizada" })
}

export const uploadDocuments = async (req, res) => {
    const userId = req.params.uid;
    const userFound = await usersService.getById(userId)
    const archivos = req.files

    const arrayDocumentos = Object.keys(archivos).map(key => ({
        name: archivos[key][0].fieldname,
        reference: archivos[key][0].filename
    }));

    userFound.documentos = arrayDocumentos
    await usersService.updateUserById(userFound._id, userFound)


    if (userFound.documentos.length >= 3) {
        changeRol(userId)
        res.send(`Felicitaciones ${userFound.first_name} subiste los archivos ${userFound.documentos.length}  y pasaste a ser un usuario PREMIUM`)
    } else {
        userFound.role === "premium" ? await changeRol(userId) : null;
        res.send(`Felicitaciones ${userFound.first_name} subiste ${userFound.documentos.length} archivo, sube los restantes y pasa a ser un usuario PREMIUM`)
    }
}

export const uploadProfiles = async (req, res) => {
    const userId = req.params.uid;
    const userFound = await usersService.getById(userId)
    const profileUploaded = req.file.filename

    userFound.fotoPerfil = profileUploaded
    await usersService.updateUserById(userFound._id, userFound)

    res.send(`Felicitaciones has subido tu foto de perfil con exito`)
}

export const uploadProducts = async (req, res) => {
    res.send(`Felicitaciones has subido la foto de un producto con exito`)
}


export const storage = multer.diskStorage({

    destination: (req, file, cb) => {
        const endpoint = req.originalUrl;
        let destinationFolder
        if (endpoint.includes("documents")) {
            destinationFolder = "uploads/documents/";
        } else if (endpoint.includes("profiles")) {
            destinationFolder = "uploads/profiles/";
        } else if (endpoint.includes("products")) {
            destinationFolder = "uploads/products/";
        }
        cb(null, destinationFolder)
    },
    filename: (req, file, cb) => {
        const endpoint = req.originalUrl;

        if (endpoint.includes("documents")) {
            switch (file.fieldname) {
                case 'identificacion':
                    cb(null, `${Date.now()}`);
                    break;
                case 'comprobante_domicilio':
                    cb(null, `${Date.now()}`);
                    break;
                case 'estado_cuenta':
                    cb(null, `${Date.now()}`);
                    break;
            }
        } else if (endpoint.includes("profiles")) {
            const timestamp = Date.now()
            cb(null, `${timestamp}`)
        } else if (endpoint.includes("products")){
            const timestamp = Date.now()
            cb(null, `${timestamp}`)
        }
    },
});








