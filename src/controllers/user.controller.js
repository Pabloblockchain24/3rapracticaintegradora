import bcrypt from "bcrypt"
import {createAccessToken,createResetToken} from "../utils.js"
import jwt from "jsonwebtoken"
import config from "../config/config.js"
import nodemailer from "nodemailer"

import {usersService,cartsService} from "../repositories/index.js"

export const logout = async (req, res) => {
    res.cookie("token", "", {
        expires: new Date(0)
    })
    res.redirect("/api/users")
    return
}

export const register = async(req,res) =>{
        const { first_name, last_name, email, age, password, role } = req.body

        try {
            const userFound = await usersService.getUserByEmail(email)
            if (userFound) return res.status(400).json(["El email ya esta registrado"])

            const hash = await bcrypt.hashSync(password, bcrypt.genSaltSync(10))


            const newUser = {first_name,last_name,email,age,role}
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

export const login = async (req,res)=>{
        const { email, password } = req.body
        const userFound = await usersService.getUserByEmail(email)
        if (!userFound) return res.status(401).json({ message: "Usuario no encontrado" })
    
        const isMatch = await bcrypt.compareSync(password, userFound.password)
        if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" })
    
        const token = await createAccessToken({ id: userFound._id })
        res.cookie("token", token)
    

        const cartFound = await cartsService.getCartById(userFound.cart)
    
            res.render("profile.hbs", {
                first_name: userFound.first_name,
                last_name: userFound.last_name,
                email: userFound.email,
                age: userFound.age,
                cart: cartFound.products,
                role: userFound.role,
            })
}

export const home = async(req,res) =>{
        const { token } = req.cookies
        if (!token) {
            return res.render("home.hbs", {
                title: "Vista login"
            })
        }
        jwt.verify(token, config.TOKEN_SECRET , async (err, user) => {
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
                    idcart: cartFound._id
                })
        })
}

export const changeRol = async(req,res) => {
    let uid = req.params.uid
    const user = await usersService.getById(uid)

    if(user.role === "premium"){
        user.role = "user"
        await usersService.updateUserById(uid, user);
        res.send({ result: "success", message: "Usuario cambio de rol de premium a user" })
    } else if (user.role === "user") {
        user.role = "premium"
        await usersService.updateUserById(uid, user);
        res.send({ result: "success", message: "Usuario cambio de rol de user a premium" })
    }else{
        res.status(401).json({message: "Cambio de rol no es posible, no es ni user ni premium"})
  }
}

export const emailRequestResetPassword = async(req,res) => {
    res.render("emailRequestResetPassword.hbs", {})
}

export const sendMail = async(req,res) => {
    const {email} = req.body
    let user = await usersService.getUserByEmail(email)
    if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

    const resetToken = await createResetToken({id: user._id})
    user.resetToken = resetToken;
    await usersService.updateUserById(user._id, user);
    const resetLink = `http://localhost:8080/api/users/passwordRequestResetPassword/${resetToken}`

    const transporter = nodemailer.createTransport({
        service:"gmail",
        port:587,
        auth:{
            user:"parcepaiva@gmail.com",
            pass:"yydj uzct rbyg bluz"
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
    transporter.sendMail(mailOptions, (error, info)=>{
        if(error){
            console.log(error)
            res.send("Error al enviar correo")
        }else{
            res.send(`Correo enviado`)
        }
    })


}

export const passwordRequestResetPassword = async(req,res) => {
    const token = req.params.tid;
    const userFound = await usersService.getUserByResetToken(token)
    if(!userFound) return  res.render("emailRequestResetPassword.hbs", {title: "Token de restablecimiento expiro o no es valido, intente nuevamente"})
    res.render('passwordRequestResetPassword.hbs', { token });

}

export const resetPassword = async(req,res) => {
    const token = req.params.tid;
    const {password} = req.body
    let userFound = await usersService.getUserByResetToken(token)

    const isSamePassword = await bcrypt.compare(password, userFound.password)
    if(isSamePassword){
        return res.render('passwordRequestResetPassword.hbs', { token, title: "Contraseña debe ser distinta a la anterior" });
    }
    const hash = await bcrypt.hashSync(password, bcrypt.genSaltSync(10))
    userFound.password = hash
    await usersService.updateUserById(userFound._id, userFound);
    res.send({ result: "success", message: "Contraseña actualizada" })
}